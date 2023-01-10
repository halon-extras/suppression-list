#include <HalonMTA.h>
#include <list>
#include <set>
#include <map>
#include <mutex>
#include <memory>
#include <fstream>
#include <string.h>
#include <syslog.h>
#include <pcre.h>

void list_open(const std::string& list, const std::string& path);
bool list_lookup(const std::string& list, const std::string& recipient);
void list_reopen(const std::string& list);

HALON_EXPORT
int Halon_version()
{
	return HALONMTA_PLUGIN_VERSION;
}

HALON_EXPORT
bool Halon_init(HalonInitContext* hic)
{
	HalonConfig* cfg;
	HalonMTA_init_getinfo(hic, HALONMTA_INIT_CONFIG, nullptr, 0, &cfg, nullptr);

	try {
		auto lists = HalonMTA_config_object_get(cfg, "lists");
		if (lists)
		{
			size_t l = 0;
			HalonConfig* list;
			while ((list = HalonMTA_config_array_get(lists, l++)))
			{
				const char* id = HalonMTA_config_string_get(HalonMTA_config_object_get(list, "id"), nullptr);
				const char* path = HalonMTA_config_string_get(HalonMTA_config_object_get(list, "path"), nullptr);
				if (!id || !path)
					continue;
				list_open(id, path);
			}
		}
		return true;
	} catch (const std::runtime_error& e) {
		syslog(LOG_CRIT, "%s", e.what());
		return false;
	}
}

HALON_EXPORT
bool Halon_command_execute(HalonCommandExecuteContext* hcec, size_t argc, const char* argv[], size_t argvl[], char** out, size_t* outlen)
{
	try {
		if (argc > 1 && strcmp(argv[0], "reload") == 0)
		{
			list_reopen(argv[1]);
			*out = strdup("OK");
			return true;
		}
		throw std::runtime_error("No such command");
	} catch (const std::runtime_error& e) {
		*out = strdup(e.what());
		return false;
	}
}

HALON_EXPORT
void suppression(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	HalonHSLValue* x;
	char* id = nullptr;
	char* text = nullptr;
	size_t textlen = 0;

	x = HalonMTA_hsl_argument_get(args, 0);
	if (x && HalonMTA_hsl_value_type(x) == HALONMTA_HSL_TYPE_STRING)
		HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &id, nullptr);
	else
		return;

	x = HalonMTA_hsl_argument_get(args, 1);
	if (x && HalonMTA_hsl_value_type(x) == HALONMTA_HSL_TYPE_STRING)
		HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &text, &textlen);
	else
		return;

	try {
		bool t = list_lookup(id, std::string(text, textlen));
		HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_BOOLEAN, &t, 0);
	} catch (const std::runtime_error& e) {
		syslog(LOG_CRIT, "%s", e.what());
	}
}

HALON_EXPORT
bool Halon_hsl_register(HalonHSLRegisterContext* ptr)
{
	HalonMTA_hsl_module_register_function(ptr, "suppression", &suppression);
	return true;
}

class suppressionlist
{
	public:
		std::string path;
		std::list<pcre*> regexs;
		std::set<std::string> emails;
		std::set<std::string> localparts;
		std::set<std::string> domains;
		~suppressionlist()
		{
			for (auto re : regexs)
				pcre_free(re);
		}
};

std::mutex listslock;
std::map<std::string, std::shared_ptr<suppressionlist>> lists;

void list_parse(const std::string& path, std::shared_ptr<suppressionlist> list)
{
	std::ifstream file(path);
	if (!file.good())
		throw std::runtime_error("Could not open file: " + path);
	std::string line;
	while (std::getline(file, line))
	{
		if (line.empty()) continue;
		if (line.size() > 2 && line[0] == '/' && line[line.size() - 1] == '/')
		{
			const char* compile_error;
			int eoffset;
			pcre* re = pcre_compile(line.substr(1, line.size() - 2).c_str(), PCRE_CASELESS, &compile_error, &eoffset, nullptr);
			if (!re)
			{
				syslog(LOG_ERR, "%s: %s: %s", path.c_str(), line.c_str(), compile_error);
				continue;
//				throw std::runtime_error(compile_error);
			}
			list->regexs.push_back(re);
		}
		else if (line[0] == '@')
			list->domains.insert(line.substr(1));
		else if (line[line.size() - 1] == '@')
			list->localparts.insert(line.substr(0, line.size() - 1));
		else
			list->emails.insert(line);
	}
	file.close();
	syslog(LOG_INFO, "suppressionlist %s loaded: %zu emails, %zu localparts, %zu domains, %zu regexes",
		path.c_str(),
		list->emails.size(),
		list->localparts.size(),
		list->domains.size(),
		list->regexs.size()
	);
}

void list_open(const std::string& list, const std::string& path)
{
	auto suppression = std::make_shared<suppressionlist>();
	suppression->path = path;

	list_parse(suppression->path, suppression);

	listslock.lock();
	lists[list] = suppression;
	listslock.unlock();
}

bool list_lookup(const std::string& list, const std::string& email)
{
	listslock.lock();
	auto l = lists.find(list);
	if (l == lists.end())
	{
		listslock.unlock();
		throw std::runtime_error("No such list id");
	}
	auto suppression = l->second;
	listslock.unlock();

	if (email.empty())
		throw std::runtime_error("No email");

	if (suppression->emails.find(email) != suppression->emails.end())
		return true;

	auto atsign = email.rfind('@');
	if (atsign != std::string::npos && atsign > 0)
	{
		auto domain = email.substr(atsign + 1);
		auto localpart = email.substr(0, atsign);
		if (!domain.empty() && l->second->domains.find(domain) != suppression->domains.end())
			return true;
		if (!localpart.empty() && l->second->localparts.find(localpart) != suppression->localparts.end())
			return true;
	}

	for (const auto & regex : suppression->regexs)
	{
		int rc = pcre_exec(regex, nullptr, email.c_str(), (int)email.size(), 0, PCRE_PARTIAL | PCRE_NO_UTF8_CHECK, nullptr, 0);
		if (rc == 0)
			return true;
	}

	return false;
}

void list_reopen(const std::string& list)
{
	listslock.lock();
	auto l = lists.find(list);
	if (l == lists.end())
	{
		listslock.unlock();
		throw std::runtime_error("No such list id");
	}
	auto currentsuppression = l->second;
	listslock.unlock();

	auto suppression = std::make_shared<suppressionlist>();
	suppression->path = currentsuppression->path;

	list_parse(suppression->path, suppression);

	listslock.lock();
	lists[list] = suppression;
	listslock.unlock();
}
