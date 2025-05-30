#include <HalonMTA.h>
#include <list>
#include <set>
#include <map>
#include <mutex>
#include <memory>
#include <fstream>
#include <string.h>
#include <syslog.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

extern char *__progname;

class suppressionlist
{
	public:
		std::string path;
		bool autoreload = true;
		std::list<pcre2_code*> regexs;
		std::set<std::string> emails;
		std::set<std::string> localparts;
		std::set<std::string> domains;
		~suppressionlist()
		{
			for (auto re : regexs)
				pcre2_code_free(re);
		}
};

static void list_open(const std::string& list, const std::string& path, bool autoreload);
static bool list_lookup(const std::string& list, const std::string& recipient);
static void list_reopen(const std::string& list);
static void list_parse(const std::string& path, std::shared_ptr<suppressionlist> list);

static std::mutex listslock;
static std::map<std::string, std::shared_ptr<suppressionlist>> lists;

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
		auto lists_ = HalonMTA_config_object_get(cfg, "lists");
		if (lists_)
		{
			size_t l = 0;
			HalonConfig* list;
			while ((list = HalonMTA_config_array_get(lists_, l++)))
			{
				const char* id = HalonMTA_config_string_get(HalonMTA_config_object_get(list, "id"), nullptr);
				const char* path = HalonMTA_config_string_get(HalonMTA_config_object_get(list, "path"), nullptr);
				const char* autoreload = HalonMTA_config_string_get(HalonMTA_config_object_get(list, "autoreload"), nullptr);
				if (!id || !path)
					continue;
				list_open(id, path, !autoreload || strcmp(autoreload, "true") == 0);
			}
		}
		return true;
	} catch (const std::runtime_error& e) {
		syslog(LOG_CRIT, "%s", e.what());
		return false;
	}
}

HALON_EXPORT
void Halon_config_reload(HalonConfig* cfg)
{
	for (auto & list : lists)
	{
		listslock.lock();
		if (!list.second->autoreload)
		{
			listslock.unlock();
			continue;
		}
		listslock.unlock();

		try {
			list_reopen(list.first);
		} catch (const std::runtime_error& e) {
			syslog(LOG_CRIT, "%s", e.what());
		}
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
		if (argc > 2 && strcmp(argv[0], "test") == 0)
		{
			bool t = list_lookup(argv[1], argv[2]);
			*out = strdup(t ? "true" : "false");
			return true;
		}
		throw std::runtime_error("No such command");
	} catch (const std::runtime_error& e) {
		*out = strdup(e.what());
		return false;
	}
}

static void suppression_list(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	HalonHSLValue* x;
	char* id = nullptr;
	char* text = nullptr;
	size_t textlen = 0;

	x = HalonMTA_hsl_argument_get(args, 0);
	if (x && HalonMTA_hsl_value_type(x) == HALONMTA_HSL_TYPE_STRING)
		HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &id, nullptr);
	else
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad id parameter", 0);
		return;
	}

	x = HalonMTA_hsl_argument_get(args, 1);
	if (x && HalonMTA_hsl_value_type(x) == HALONMTA_HSL_TYPE_STRING)
		HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &text, &textlen);
	else
	{
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, "Bad email parameter", 0);
		return;
	}

	try {
		bool t = list_lookup(id, std::string(text, textlen));
		HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_BOOLEAN, &t, 0);
	} catch (const std::runtime_error& ex) {
		HalonHSLValue* e = HalonMTA_hsl_throw(hhc);
		HalonMTA_hsl_value_set(e, HALONMTA_HSL_TYPE_EXCEPTION, ex.what(), 0);
		return;
	}
}

HALON_EXPORT
bool Halon_hsl_register(HalonHSLRegisterContext* ptr)
{
	HalonMTA_hsl_module_register_function(ptr, "suppression_list", &suppression_list);
	return true;
}

static void list_parse(const std::string& path, std::shared_ptr<suppressionlist> list)
{
	std::ifstream file(path);
	if (!file.good())
		throw std::runtime_error("Could not open file: " + path);
	std::string line;
	size_t errors = 0;
	while (std::getline(file, line))
	{
		if (line.empty()) continue;
		if (line[0] == '#') continue; // skip comments
		if (line.size() > 2 && line[0] == '/' && line[line.size() - 1] == '/')
		{
			int errorcode;
			PCRE2_SIZE offset;
			pcre2_code* re = pcre2_compile((PCRE2_SPTR)line.substr(1, line.size() - 2).c_str(), PCRE2_ZERO_TERMINATED, PCRE2_CASELESS, &errorcode, &offset, nullptr);
			if (!re)
			{
				PCRE2_UCHAR buffer[256];
				pcre2_get_error_message(errorcode, buffer, sizeof(buffer));
				syslog(LOG_ERR, "%s: %s: %s", path.c_str(), line.c_str(), buffer);
				++errors;
				continue;
			}
			// pcre2_jit_compile(re, PCRE2_JIT_COMPLETE); // too low complex regex to get any benfit
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
	if (strcmp(__progname, "smtpd") == 0)
		syslog(LOG_INFO, "suppression-list %s loaded: %zu emails, %zu localparts, %zu domains, %zu regexes, %zu regex-errors",
			path.c_str(),
			list->emails.size(),
			list->localparts.size(),
			list->domains.size(),
			list->regexs.size(),
			errors
		);
}

static void list_open(const std::string& list, const std::string& path, bool autoreload)
{
	auto suppression = std::make_shared<suppressionlist>();
	suppression->path = path;
	suppression->autoreload = autoreload;

	list_parse(suppression->path, suppression);

	listslock.lock();
	lists[list] = suppression;
	listslock.unlock();
}

static bool list_lookup(const std::string& list, const std::string& email)
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

	pcre2_match_data* match_data = pcre2_match_data_create(1, nullptr);
	for (const auto & regex : suppression->regexs)
	{
		int ret = pcre2_match(regex,
								(PCRE2_SPTR)email.c_str(),
								email.size(),
								0,
								PCRE2_NO_UTF_CHECK,
								match_data,
								nullptr);
		if (ret >= 0)
		{
			pcre2_match_data_free(match_data);
			return true;
		}
	}

	pcre2_match_data_free(match_data);
	return false;
}

static void list_reopen(const std::string& list)
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
	suppression->autoreload = currentsuppression->autoreload;

	list_parse(suppression->path, suppression);

	listslock.lock();
	lists[list] = suppression;
	listslock.unlock();
}
