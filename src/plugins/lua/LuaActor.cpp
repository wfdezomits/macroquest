/*
 * MacroQuest: The extension platform for EverQuest
 * Copyright (C) 2002-2022 MacroQuest Authors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "pch.h"

#include "mq/base/Common.h"
#include "mq/proto/PostOffice.h"
#include "mq/Plugin.h"

#include "Actor.pb.h"

#include "LuaActor.h"
#include "LuaThread.h"
#include "LuaCoroutine.h"

// includes for datatype conversions to proto
#include "imgui.h"

#include "common/StringUtils.h"

namespace mq::lua {
using namespace mq::postoffice;
using Mailbox = PostOffice::Mailbox;

namespace messaging = proto::lua::actor;
namespace routing = proto;

// create a single mailbox to the postoffice as an interface. this will ensure that we don't have mailbox
// naming collisions with internal objects (or other non-lua objects) and restricts routing of lua messages
// to other lua actors, which we want because we don't have any serialization bindings for any other types
// of messages.
static std::shared_ptr<Mailbox> s_mailbox;

// kind of boring for now, every message we expect is a LuaMessage
// we can expand this later, but routing within actors will probably
// be the main method of routing, not in the main mailbox
enum class LuaMessageID : uint16_t
{
	LuaMessage = 0, // message payload is a Variant (an arbitrary lua data)
};

sol::object DeserProto(const messaging::Variant& data, sol::state_view s);
messaging::Variant SerProto(const sol::object&);
struct lua_LuaMessage
{
	messaging::LuaMessage message;
	routing::Address sender;

	lua_LuaMessage(messaging::LuaMessage&& message_, routing::Address&& sender_)
		: message(std::move(message_))
		, sender(std::move(sender_))
	{}

	sol::object Get(sol::this_state s)
	{
		if (message.has_data())
			return DeserProto(message.data(), s);

		return sol::nil;
	}

	void Reply(sol::object reply)
	{
		if (s_mailbox && (sender.has_account() || sender.has_server() || sender.has_character()) && message.has_sender())
		{
			messaging::LuaMessage response;

			messaging::LuaAddress to;
			to.set_mailbox(message.sender().mailbox());
			if (message.sender().has_script()) to.set_script(message.sender().script());
			*response.mutable_destination() = to;

			if (message.has_destination())
			{
				messaging::LuaAddress from;
				from.set_mailbox(message.destination().mailbox());
				if (message.destination().has_script()) from.set_script(message.destination().script());
				*response.mutable_sender() = from;
			}

			*response.mutable_data() = SerProto(reply);

			s_mailbox->Post(sender, LuaMessageID::LuaMessage, response);
		}
	}
};

struct CallbackInstance
{
	std::shared_ptr<LuaCoroutine> coroutine;
	lua_LuaMessage message;
	bool run_started = false;

	// the thread lifetime is necessarily longer than this CallbackInstance because if the thread goes
	// down, the mailboxes will be closed
	CallbackInstance(const std::shared_ptr<LuaThread>& thread, const sol::function& callback, lua_LuaMessage&& message)
		: message(std::move(message))
	{
		auto [_, lua_thread] = thread->CreateThread();
		coroutine = LuaCoroutine::Create(lua_thread, thread.get());
		coroutine->coroutine = sol::coroutine(lua_thread.state(), callback);
	}
};

/**
 * A local lua mailbox type. The postoffice mailbox will route messages to these mailboxes and provide
 * addressing to route messages from these mailboxes. These are the actual lua interfaces into userland,
 * and they will have message processing callbacks defined in lua space by the user.
 */
class LuaMailbox
{
public:
	static std::shared_ptr<LuaMailbox> Register(const std::string& name, const sol::function& callback, sol::this_state s);
	void Unregister(sol::this_state s);

	void Send(sol::table header, sol::object payload);
	void Receive(messaging::LuaMessage&& message, routing::Address&& address);
	bool Process();

	const std::string& GetName() { return m_name; }
	std::shared_ptr<LuaThread> GetThread() { return m_thread.lock(); }

	LuaMailbox(std::string_view name, const sol::function& callback, const std::shared_ptr<LuaThread>& thread);

private:
	std::string m_name;
	sol::function m_callback;
	std::weak_ptr<LuaThread> m_thread;
	std::vector<CallbackInstance> m_queue;
	std::vector<lua_LuaMessage> m_deadLetterQueue;
};

// now create a map of internal lua mailboxes to route to
static ci_unordered::multimap<std::string, std::weak_ptr<LuaMailbox>> s_mailboxes;

sol::object DeserProto(const messaging::Variant& data, sol::state_view s)
{
	switch (data.value_case())
	{
	case messaging::Variant::ValueCase::kNumber:
		return sol::make_object(s, data.number());
	case messaging::Variant::ValueCase::kBoolean:
		return sol::make_object(s, data.boolean());
	case messaging::Variant::ValueCase::kStr:
		return sol::make_object(s, data.str());
	case messaging::Variant::ValueCase::kTable:
	{
		auto table = s.create_table(0, static_cast<int>(data.table().entries().size()));
		for (const auto& [k, v] : data.table().entries())
		{
			table[k] = DeserProto(v, s);
		}

		return sol::make_object(s, table);
	}
	case messaging::Variant::ValueCase::kImvec2:
		return sol::make_object(s, ImVec2(
			data.imvec2().x(),
			data.imvec2().y()));
	case messaging::Variant::ValueCase::kImvec4:
		return sol::make_object(s, ImVec4(
			data.imvec4().x(),
			data.imvec4().y(),
			data.imvec4().z(),
			data.imvec4().w()
		));
	default:
		return sol::nil;
	}
}

messaging::Variant SerProto(const sol::object& data)
{
	messaging::Variant variant;

	switch (data.get_type())
	{
	case sol::type::string:
		variant.set_str(data.as<std::string>());
		break;
	case sol::type::number:
		variant.set_number(data.as<double>());
		break;
	case sol::type::boolean:
		variant.set_boolean(data.as<bool>());
		break;
	case sol::type::table:
	{
		messaging::Table table;
		auto entries = *table.mutable_entries();
		for (const auto& [k, v] : data.as<sol::table>())
		{
			if (k.is<std::string_view>())
			{
				// a limitation of proto: keys can only be strings
				entries[k.as<std::string_view>()] = SerProto(v);
			}
		}

		*variant.mutable_table() = table;
		break;
	}
	case sol::type::userdata:
		if (data.is<ImVec2>())
		{
			auto vec = data.as<ImVec2>();
			*variant.mutable_imvec2() = messaging::ImVec2();
			(*variant.mutable_imvec2()).set_x(vec.x);
			(*variant.mutable_imvec2()).set_y(vec.y);
		}
		else if (data.is<ImVec4>())
		{
			auto vec = data.as<ImVec4>();
			*variant.mutable_imvec4() = messaging::ImVec4();
			(*variant.mutable_imvec4()).set_x(vec.x);
			(*variant.mutable_imvec4()).set_y(vec.y);
			(*variant.mutable_imvec4()).set_z(vec.z);
			(*variant.mutable_imvec4()).set_w(vec.w);
		}
		break;
	default:
		break;
	}

	return variant;
}

std::shared_ptr<LuaMailbox> LuaMailbox::Register(const std::string& name, const sol::function& callback, sol::this_state s)
{
	// need to construct the shared_ptr here or it will go out of scope and GC
	auto mailbox = std::make_shared<LuaMailbox>(name, callback, LuaThread::get_from(s));

	// if we can't place the mailbox in the map for some reason, then return a nullptr
	if (s_mailboxes.emplace(name, mailbox) == s_mailboxes.end())
		mailbox.reset();

	return mailbox;
}

void LuaMailbox::Unregister(sol::this_state s)
{
	if (auto thread = LuaThread::get_from(s))
	{
		auto range = s_mailboxes.equal_range(m_name);
		for (auto& mailbox_it = range.first; mailbox_it != range.second;)
		{
			auto mailbox = mailbox_it->second.lock();
			if (!mailbox)
			{
				mailbox_it = s_mailboxes.erase(mailbox_it);
			}
			else
			{
				auto mailbox_thread = mailbox->m_thread.lock();
				if (!mailbox_thread || ci_equals(mailbox_thread->GetName(), thread->GetName()))
					mailbox_it = s_mailboxes.erase(mailbox_it);
				else
					++mailbox_it;
			}
		}
	}
}

LuaMailbox::LuaMailbox(std::string_view name, const sol::function& callback, const std::shared_ptr<LuaThread>& thread)
	: m_name(name)
	, m_callback(callback)
	, m_thread(thread) // this can potentially be empty, we will need to account for that
{}

// TODO: create a helper function to create well-formed headers
void LuaMailbox::Send(sol::table header, sol::object payload)
{
	if (s_mailbox)
	{
		// parse the header for routing information
		std::optional<std::string> mailbox = header["mailbox"];

		// this header is only valid if mailbox exists, everything else is optional
		if (mailbox)
		{
			// finish parsing the header for any address data
			routing::Address addr;

			// any ambiguity in address means that it will get sent to all mailboxes
			// that match. In this way, Send is simultaneously a "tell" and a "shout"
			std::optional<std::string> account = header["account"];
			if (account) addr.set_account(*account);

			std::optional<std::string> server = header["server"];
			if (server) addr.set_server(*server);

			std::optional<std::string> character = header["character"];
			if (character) addr.set_character(*character);

			// the mailbox will always be lua because we want to route the messages through
			// the target's lua actor handler.
			addr.set_mailbox("lua");

			// then send the message using the pipe mailbox (this could potentially send a message back here!)
			messaging::LuaMessage message;

			messaging::LuaAddress destination;
			destination.set_mailbox(*mailbox);
			std::optional<std::string> script = header["script"];
			if (script) destination.set_script(*script);
			*message.mutable_destination() = destination;

			messaging::LuaAddress sender;
			sender.set_mailbox(m_name);
			if (auto thread = GetThread()) sender.set_script(thread->GetName());
			*message.mutable_sender() = sender;

			*message.mutable_data() = SerProto(payload);

			s_mailbox->Post(addr, LuaMessageID::LuaMessage, message);
		}
	}
}

void LuaMailbox::Receive(messaging::LuaMessage&& message, routing::Address&& address)
{
	lua_LuaMessage lua_message(std::move(message), std::move(address));
	if (auto thread = m_thread.lock())
	{
		// first empty the DLQ in order
		for (auto dead_letter : m_deadLetterQueue)
		{
			dead_letter.message.mutable_destination()->set_script(thread->GetName());
			m_queue.emplace_back(thread, m_callback, std::move(dead_letter));
		}

		m_deadLetterQueue.clear();

		// then add the new message
		lua_message.message.mutable_destination()->set_script(thread->GetName());
		m_queue.emplace_back(thread, m_callback, std::move(lua_message));
	}
	else
	{
		m_deadLetterQueue.emplace_back(std::move(lua_message));
	}
}

bool LuaMailbox::Process()
{
	if (auto thread = m_thread.lock())
	{
		m_queue.erase(std::remove_if(m_queue.begin(), m_queue.end(),
			[this, &thread](CallbackInstance& callback)
			{
				if (thread->ShouldYield()) return false;

				if (!callback.coroutine) return true;
				if (!callback.coroutine->ShouldRun()) return false;

				// this breaks if we don't remove the message after the first call
				CoroutineResult result;
				if (callback.run_started)
				{
					result = callback.coroutine->RunCoroutine();
				}
				else
				{
					auto result = callback.coroutine->RunCoroutine({ sol::make_object(thread->GetState(), callback.message) });
					callback.run_started = true; // note the mutation, this is why we have a ref instead of a constref
				}

				return !result || result->status() != sol::call_status::yielded;
			}), m_queue.end());

		return true;
	}

	return false;
}

// TODO: are these useful? I'm not even sure it would work...
sol::object StatelessIterator(sol::object, sol::object k, sol::this_state s)
{
	if (s_mailboxes.begin() == s_mailboxes.end())
		return sol::lua_nil;

	if (k == sol::lua_nil)
	{
		// if any of these mailboxes are invalid, just erase them from the map, this will
		// return as soon as a valid mailbox is found.
		for (auto& it = s_mailboxes.begin(); it != s_mailboxes.end(); it = s_mailboxes.erase(it))
		{
			if (auto ptr = it->second.lock())
				return sol::make_object(s, ptr);
		}

		return sol::lua_nil;
	}

	if (k.is<std::shared_ptr<LuaMailbox>>())
	{
		auto ptr = k.as<std::shared_ptr<LuaMailbox>>();
		auto it = std::find_if(s_mailboxes.begin(), s_mailboxes.end(),
			[&ptr](const std::pair<std::string, std::weak_ptr<LuaMailbox>>& pair)
			{
				return pair.second.lock() == ptr;
			});

		if (it != s_mailboxes.end()) ++it;

		// guaranteed to not be expired because the equality check in the find would be false if it was
		if (it != s_mailboxes.end())
			return sol::make_object(s, it->second.lock());
	}

	return sol::lua_nil;
}

sol::object Iterator(sol::this_state s)
{
	return sol::make_object(s, std::make_tuple(StatelessIterator, sol::lua_nil, sol::lua_nil));
}

// TODO: add address storage for connected remote actors (ident and drop)
void LuaActors::RegisterLua(std::optional<sol::table>& actors, sol::state_view s)
{
	if (!actors)
	{
		actors = s.create_table();
		actors->new_usertype<LuaMailbox>(
			"mailbox", sol::no_constructor,
			"send", &LuaMailbox::Send,
			"unregister", &LuaMailbox::Unregister);

		actors->new_usertype<lua_LuaMessage>(
			"message", sol::no_constructor,
			"message", sol::property(&lua_LuaMessage::Get),
			"reply", &lua_LuaMessage::Reply,
			sol::meta_function::call, &lua_LuaMessage::Get);

		actors->set_function("register", &LuaMailbox::Register);
		actors->set_function("iter", &Iterator);
	}
}

void LuaActors::Start()
{
	s_mailbox = GetPostOffice().CreateAndAddMailbox("lua",
		[](ProtoMessagePtr&& message)
		{
			if (static_cast<LuaMessageID>(message->GetMessageId()) == LuaMessageID::LuaMessage)
			{
				// all we do here is forward messages to their lua mailboxes
				auto lua_message = message->Parse<messaging::LuaMessage>();
				if (lua_message.has_destination())
				{
					auto mailboxes = s_mailboxes.equal_range(lua_message.destination().mailbox());
					for (auto& mailbox_it = mailboxes.first; mailbox_it != mailboxes.second;)
					{
						if (auto ptr = mailbox_it->second.lock())
						{
							if (lua_message.destination().has_script())
							{
								auto thread = ptr->GetThread();
								if (thread && ci_equals(thread->GetName(), lua_message.destination().script()))
								{
									// the lua_message needs to be copied, use the copy ctor to do it explicitly
									ptr->Receive(messaging::LuaMessage(lua_message), message->GetSender().value_or(routing::Address()));
								}
							}
							else
							{
								// the lua_message needs to be copied, use the copy ctor to do it explicitly
								ptr->Receive(messaging::LuaMessage(lua_message), message->GetSender().value_or(routing::Address()));
							}

							++mailbox_it;
						}
						else
						{
							mailbox_it = s_mailboxes.erase(mailbox_it);
						}
					}
				}
			}
		});
}

void LuaActors::Stop()
{
	GetPostOffice().RemoveMailbox("lua");
}

void LuaActors::Process()
{
	for (auto& mailbox_it = s_mailboxes.begin(); mailbox_it != s_mailboxes.end();)
	{
		auto ptr = mailbox_it->second.lock();
		if (ptr && ptr->Process())
			++mailbox_it;
		else
		{
			mailbox_it = s_mailboxes.erase(mailbox_it);
		}
	}
}

} // namespace mq::lua
