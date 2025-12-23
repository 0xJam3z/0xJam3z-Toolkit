#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct Config {
    std::string input;
    std::string ports = "80,443";
    std::string rate = "10000";
    std::string list_file = "list";
    std::string output_file = "opendomains";
    bool no_download = false;
    bool list_mode = false;
    std::string country_filter;
};

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static std::string trim(const std::string &s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

static std::vector<std::string> split_ws(const std::string &line) {
    std::istringstream iss(line);
    std::vector<std::string> tokens;
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

static bool is_ipv4(const std::string &ip) {
    if (ip.find(':') != std::string::npos) {
        return false;
    }
    std::istringstream iss(ip);
    std::string part;
    int parts = 0;
    while (std::getline(iss, part, '.')) {
        if (part.empty() || part.size() > 3) {
            return false;
        }
        for (char c : part) {
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                return false;
            }
        }
        int value = std::stoi(part);
        if (value < 0 || value > 255) {
            return false;
        }
        ++parts;
    }
    return parts == 4;
}

static std::string quote_path(const std::string &path) {
#ifdef _WIN32
    return "\"" + path + "\"";
#else
    return "'" + path + "'";
#endif
}

static std::optional<std::string> find_in_path(const std::string &name) {
    const char *path_env = std::getenv("PATH");
    if (!path_env) {
        return std::nullopt;
    }
#ifdef _WIN32
    const char sep = ';';
#else
    const char sep = ':';
#endif
    std::string paths = path_env;
    std::istringstream iss(paths);
    std::string dir;
    while (std::getline(iss, dir, sep)) {
        if (dir.empty()) {
            continue;
        }
        fs::path candidate = fs::path(dir) / name;
        if (fs::exists(candidate)) {
            return candidate.string();
        }
    }
    return std::nullopt;
}

static bool run_command(const std::string &cmd) {
    std::cout << "[cmd] " << cmd << std::endl;
    int result = std::system(cmd.c_str());
    return result == 0;
}

static std::optional<std::string> ensure_masscan(const fs::path &base_dir, bool no_download) {
#ifdef _WIN32
    std::string exe_name = "masscan.exe";
#else
    std::string exe_name = "masscan";
#endif
    if (auto found = find_in_path(exe_name)) {
        return found;
    }

    fs::path local_bin = base_dir / "bin" / exe_name;
    if (fs::exists(local_bin)) {
        return local_bin.string();
    }

    if (no_download) {
        std::cerr << "masscan not found and downloads disabled." << std::endl;
        return std::nullopt;
    }

    fs::path third_party = base_dir / "third_party";
    fs::path repo_dir = third_party / "masscan";
    fs::create_directories(third_party);

    if (!fs::exists(repo_dir)) {
        if (!run_command("git clone https://github.com/robertdavidgraham/masscan.git " + quote_path(repo_dir.string()))) {
            std::cerr << "Failed to clone masscan." << std::endl;
            return std::nullopt;
        }
    }

#ifdef _WIN32
    std::cerr << "masscan requires a Windows build toolchain. Build it in " << repo_dir << " and place the binary in "
              << (base_dir / "bin") << "." << std::endl;
    return std::nullopt;
#else
    if (!run_command("make -C " + quote_path(repo_dir.string()))) {
        std::cerr << "Failed to build masscan." << std::endl;
        return std::nullopt;
    }
    fs::create_directories(base_dir / "bin");
    fs::path built = repo_dir / "bin" / "masscan";
    if (!fs::exists(built)) {
        std::cerr << "masscan build did not produce expected binary." << std::endl;
        return std::nullopt;
    }
    fs::copy_file(built, local_bin, fs::copy_options::overwrite_existing);
    return local_bin.string();
#endif
}

static std::optional<std::string> ensure_zgrab2(const fs::path &base_dir, bool no_download) {
#ifdef _WIN32
    std::string exe_name = "zgrab2.exe";
#else
    std::string exe_name = "zgrab2";
#endif
    if (auto found = find_in_path(exe_name)) {
        return found;
    }

    fs::path local_bin = base_dir / "bin" / exe_name;
    if (fs::exists(local_bin)) {
        return local_bin.string();
    }

    if (no_download) {
        std::cerr << "zgrab2 not found and downloads disabled." << std::endl;
        return std::nullopt;
    }

    fs::path third_party = base_dir / "third_party";
    fs::path repo_dir = third_party / "zgrab2";
    fs::create_directories(third_party);

    if (!fs::exists(repo_dir)) {
        if (!run_command("git clone https://github.com/zmap/zgrab2.git " + quote_path(repo_dir.string()))) {
            std::cerr << "Failed to clone zgrab2." << std::endl;
            return std::nullopt;
        }
    }

    fs::create_directories(base_dir / "bin");
#ifdef _WIN32
    std::string build_cmd = "cd /d " + quote_path(repo_dir.string()) + " && go build -o " + quote_path(local_bin.string()) + " ./cmd/zgrab2";
#else
    std::string build_cmd = "cd " + quote_path(repo_dir.string()) + " && go build -o " + quote_path(local_bin.string()) + " ./cmd/zgrab2";
#endif
    if (!run_command(build_cmd)) {
        std::cerr << "Failed to build zgrab2. Ensure Go is installed." << std::endl;
        return std::nullopt;
    }

    return local_bin.string();
}

static bool build_list_from_asn_json(const fs::path &json_path, const fs::path &list_path,
                                     const std::string &country_filter) {
    std::ifstream in(json_path);
    if (!in) {
        std::cerr << "Failed to open " << json_path << std::endl;
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::regex start_re("\\\"start_ip\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    std::regex end_re("\\\"end_ip\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    std::regex country_re("\\\"country_name\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

    std::vector<std::string> starts;
    std::vector<std::string> ends;
    std::vector<std::string> countries;

    for (auto it = std::sregex_iterator(content.begin(), content.end(), start_re); it != std::sregex_iterator(); ++it) {
        starts.push_back((*it)[1].str());
    }
    for (auto it = std::sregex_iterator(content.begin(), content.end(), end_re); it != std::sregex_iterator(); ++it) {
        ends.push_back((*it)[1].str());
    }
    for (auto it = std::sregex_iterator(content.begin(), content.end(), country_re); it != std::sregex_iterator(); ++it) {
        countries.push_back((*it)[1].str());
    }

    if (starts.empty() || ends.empty() || starts.size() != ends.size()) {
        std::cerr << "Could not parse start/end IPs from " << json_path << std::endl;
        return false;
    }

    std::ofstream out(list_path);
    if (!out) {
        std::cerr << "Failed to write " << list_path << std::endl;
        return false;
    }

    size_t count = 0;
    for (size_t i = 0; i < starts.size(); ++i) {
        if (!country_filter.empty()) {
            if (i >= countries.size()) {
                continue;
            }
            if (to_lower(countries[i]) != to_lower(country_filter)) {
                continue;
            }
        }
        if (is_ipv4(starts[i]) && is_ipv4(ends[i])) {
            out << starts[i] << "-" << ends[i] << "\n";
            ++count;
        }
    }

    std::cout << "Wrote " << count << " IPv4 ranges to " << list_path << std::endl;
    return count > 0;
}

static bool write_single_input_list(const fs::path &list_path, const std::string &input) {
    std::ofstream out(list_path);
    if (!out) {
        std::cerr << "Failed to write " << list_path << std::endl;
        return false;
    }
    out << input << "\n";
    return true;
}

static bool parse_masscan_results(const fs::path &masscan_file, const fs::path &out80, const fs::path &out443) {
    std::ifstream in(masscan_file);
    if (!in) {
        std::cerr << "Failed to read " << masscan_file << std::endl;
        return false;
    }

    std::ofstream out_80(out80);
    std::ofstream out_443(out443);
    if (!out_80 || !out_443) {
        std::cerr << "Failed to open output IP files." << std::endl;
        return false;
    }

    std::string line;
    size_t count_80 = 0;
    size_t count_443 = 0;
    while (std::getline(in, line)) {
        auto tokens = split_ws(line);
        if (tokens.size() >= 4 && tokens[0] == "open" && tokens[1] == "tcp") {
            const std::string &port = tokens[2];
            const std::string &ip = tokens[3];
            if (port == "80") {
                out_80 << ip << "\n";
                ++count_80;
            } else if (port == "443") {
                out_443 << ip << "\n";
                ++count_443;
            }
        }
    }

    std::cout << "Open port 80 IPs: " << count_80 << std::endl;
    std::cout << "Open port 443 IPs: " << count_443 << std::endl;
    return true;
}

static std::string unescape_json_string(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c != '\\' || i + 1 >= s.size()) {
            out.push_back(c);
            continue;
        }
        char n = s[++i];
        switch (n) {
            case '\\': out.push_back('\\'); break;
            case '"': out.push_back('"'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                if (i + 4 < s.size()) {
                    std::string hex = s.substr(i + 1, 4);
                    unsigned int code = 0;
                    std::istringstream iss(hex);
                    iss >> std::hex >> code;
                    if (code <= 0x7F) {
                        out.push_back(static_cast<char>(code));
                    } else {
                        out.push_back('?');
                    }
                    i += 4;
                }
                break;
            }
            default:
                out.push_back(n);
                break;
        }
    }
    return out;
}

static std::optional<std::string> extract_json_string_value(const std::string &line, const std::string &key) {
    std::regex re(key + "\\s*:\\s*\\\"((?:[^\\\\\\\"]|\\\\.)*)\\\"");
    std::smatch match;
    if (std::regex_search(line, match, re)) {
        return unescape_json_string(match[1].str());
    }
    return std::nullopt;
}

static std::string extract_title(const std::string &html) {
    std::string lower = to_lower(html);
    size_t start = lower.find("<title");
    if (start == std::string::npos) {
        return "No title found";
    }
    size_t gt = lower.find('>', start);
    if (gt == std::string::npos) {
        return "No title found";
    }
    size_t end = lower.find("</title>", gt);
    if (end == std::string::npos || end <= gt) {
        return "No title found";
    }
    std::string title = html.substr(gt + 1, end - gt - 1);
    title = trim(title);
    if (title.empty()) {
        return "No title found";
    }
    return title;
}

static bool parse_zgrab_titles(const fs::path &zgrab_file, std::ofstream &out) {
    std::ifstream in(zgrab_file);
    if (!in) {
        std::cerr << "Failed to read " << zgrab_file << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(in, line)) {
        auto ip = extract_json_string_value(line, "\\\"ip\\\"");
        auto body = extract_json_string_value(line, "\\\"body\\\"");
        if (!ip) {
            continue;
        }
        if (!body) {
            out << "IP: " << *ip << " - No response body found" << "\n";
            continue;
        }
        std::string title = extract_title(*body);
        out << "IP: " << *ip << " - Title: " << title << "\n";
    }

    return true;
}

static void print_usage() {
    std::cout << "Usage: 0xjam3z-scanner <ip|cidr|range|list|country_asn.json> [options]\n"
              << "Options:\n"
              << "  --ports <list>        Ports to scan (default: 80,443)\n"
              << "  --rate <n>            Masscan rate (default: 10000)\n"
              << "  --no-download         Do not auto-download tools\n"
              << "  --output <file>       Output file for titles (default: opendomains)\n"
              << "  --list                Treat input as a pre-built masscan list file\n"
              << "  --country <name>      Filter country_name when parsing country_asn.json\n"
              << "  --help                Show this help\n";
}

static bool parse_args(int argc, char **argv, Config &cfg) {
    if (argc < 2) {
        print_usage();
        return false;
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage();
            return false;
        } else if (arg == "--ports" && i + 1 < argc) {
            cfg.ports = argv[++i];
        } else if (arg == "--rate" && i + 1 < argc) {
            cfg.rate = argv[++i];
        } else if (arg == "--no-download") {
            cfg.no_download = true;
        } else if (arg == "--output" && i + 1 < argc) {
            cfg.output_file = argv[++i];
        } else if (arg == "--list") {
            cfg.list_mode = true;
        } else if (arg == "--country" && i + 1 < argc) {
            cfg.country_filter = argv[++i];
        } else if (arg.rfind("--", 0) == 0) {
            std::cerr << "Unknown option: " << arg << std::endl;
            return false;
        } else if (cfg.input.empty()) {
            cfg.input = arg;
        } else {
            std::cerr << "Unexpected argument: " << arg << std::endl;
            return false;
        }
    }

    if (cfg.input.empty()) {
        print_usage();
        return false;
    }

    return true;
}

int main(int argc, char **argv) {
    Config cfg;
    if (!parse_args(argc, argv, cfg)) {
        return 1;
    }

    fs::path base_dir = fs::current_path();
    fs::create_directories(base_dir / "bin");
    fs::create_directories(base_dir / "third_party");

    auto masscan = ensure_masscan(base_dir, cfg.no_download);
    if (!masscan) {
        std::cerr << "masscan is required." << std::endl;
        return 1;
    }
    auto zgrab2 = ensure_zgrab2(base_dir, cfg.no_download);
    if (!zgrab2) {
        std::cerr << "zgrab2 is required." << std::endl;
        return 1;
    }

    fs::path input_path(cfg.input);
    fs::path list_path = base_dir / cfg.list_file;
    bool list_ready = false;

    if (fs::exists(input_path)) {
        if (input_path.extension() == ".json") {
            list_ready = build_list_from_asn_json(input_path, list_path, cfg.country_filter);
        } else {
            if (!cfg.country_filter.empty()) {
                std::cerr << "--country requires a country_asn.json input." << std::endl;
                return 1;
            }
            if (cfg.list_mode) {
                list_ready = fs::equivalent(input_path, list_path);
                if (!list_ready) {
                    fs::copy_file(input_path, list_path, fs::copy_options::overwrite_existing);
                    list_ready = true;
                }
            } else {
                list_ready = write_single_input_list(list_path, cfg.input);
            }
        }
    } else {
        if (cfg.list_mode) {
            std::cerr << "List file not found: " << input_path << std::endl;
            return 1;
        }
        if (!cfg.country_filter.empty()) {
            std::cerr << "--country requires a country_asn.json input." << std::endl;
            return 1;
        }
        list_ready = write_single_input_list(list_path, cfg.input);
    }

    if (!list_ready) {
        std::cerr << "Failed to prepare list file for masscan." << std::endl;
        return 1;
    }

    fs::path masscan_output = base_dir / "masscan_results.txt";
    fs::path open80 = base_dir / "open_ips80.txt";
    fs::path open443 = base_dir / "open_ips443.txt";
    fs::path zgrab80 = base_dir / "zgrab_results_80.json";
    fs::path zgrab443 = base_dir / "zgrab_results_443.json";

    std::string masscan_cmd = quote_path(*masscan) + " -p" + cfg.ports + " -iL " + quote_path(list_path.string()) +
                              " --rate=" + cfg.rate + " --exclude 255.255.255.255 --wait 0 -oL " + quote_path(masscan_output.string());
    if (!run_command(masscan_cmd)) {
        std::cerr << "masscan failed. You may need elevated privileges." << std::endl;
        return 1;
    }

    if (!parse_masscan_results(masscan_output, open80, open443)) {
        return 1;
    }

    if (fs::file_size(open80) > 0) {
        std::string zgrab_cmd_80 = quote_path(*zgrab2) + " http --port 80 --input-file " + quote_path(open80.string()) +
                                   " --max-redirects 0 --output-file " + quote_path(zgrab80.string());
        if (!run_command(zgrab_cmd_80)) {
            std::cerr << "zgrab2 failed for port 80." << std::endl;
        }
    }

    if (fs::file_size(open443) > 0) {
        std::string zgrab_cmd_443 = quote_path(*zgrab2) + " http --port 443 --input-file " + quote_path(open443.string()) +
                                    " --max-redirects 0 --output-file " + quote_path(zgrab443.string());
        if (!run_command(zgrab_cmd_443)) {
            std::cerr << "zgrab2 failed for port 443." << std::endl;
        }
    }

    std::ofstream out(cfg.output_file);
    if (!out) {
        std::cerr << "Failed to open output file: " << cfg.output_file << std::endl;
        return 1;
    }

    if (fs::exists(zgrab80)) {
        parse_zgrab_titles(zgrab80, out);
    }
    if (fs::exists(zgrab443)) {
        parse_zgrab_titles(zgrab443, out);
    }

    std::cout << "Success" << std::endl;
    return 0;
}
