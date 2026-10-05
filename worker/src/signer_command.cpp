#include <rp/signer_command.hpp>

#include <rp/cert_export.hpp>
#include <rp/cli.hpp>
#include <rp/config.hpp>
#include <rp/signer.hpp>

#include "file_read.hpp"
#include "path_utf8.hpp"
#include "utf16.hpp"

#include <cstddef>
#include <filesystem>
#include <format>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace rp {

namespace {

// `code`, once the answer is out. An answer that didn't reach `out` isn't one:
// exit 0 or 5 would say what no line did.
int answered(std::ostream& out, std::ostream& err, int code)
{
    out.flush();
    if (!out) {
        err << "signer error: the answer couldn't be written\n";
        return exit_code::config;
    }
    return code;
}

// `rpworker signer public-key`.
int run_public_key(std::ostream& out, std::ostream& err, const SignerCommandEnv& env)
{
    // One return after the handler (see signer.cpp). Anything but a
    // ConfigError goes to run_cli, whose line never shows a message.
    Secrets secrets;
    std::optional<std::string> problem;
    try {
        secrets = env.load_secrets();
    } catch (const ConfigError& e) {
        problem = e.what();
    }
    if (problem) {
        err << "config error: " << *problem << '\n';
        return exit_code::config;
    }
    // The pipeline's two texts (run_pipeline.cpp), the first without its
    // "--evidence signs the result": no run is asked for here.
    if (!secrets.signing_key_base64 || secrets.signing_key_base64->empty()) {
        err << "config error: " << kEnvSigningKeyBase64 << " is not set\n";
        return exit_code::config;
    }
    const std::optional<SigningKey> key = SigningKey::from_base64(*secrets.signing_key_base64);
    // The text isn't needed again, whatever it was.
    secure_wipe(*secrets.signing_key_base64);
    if (!key) {
        err << "config error: " << kEnvSigningKeyBase64
            << " is not an Ed25519 private key (Base64 of PKCS#8 DER)\n";
        return exit_code::config;
    }
    // The public half only: the PEM ends its own last line.
    out << key->public_key_pem() << "key " << key->key_id() << '\n';
    return answered(out, err, exit_code::ok);
}

// A file's name for a note: printable ASCII as it is, a backslash and anything
// else by its code point, so no name can end a line or start another.
// (verify_bundle.py writes its notes the same way, but for the short forms of
// a backslash, a tab and a line end, which no file name on Windows holds.)
std::string printable(std::string_view name)
{
    // list_folder's names are UTF-8, so the conversion never fails here.
    const std::wstring wide = utf8_to_utf16(name).value_or(std::wstring{});
    std::string text;
    for (std::size_t i = 0; i < wide.size(); ++i) {
        unsigned long c = static_cast<unsigned long>(wide[i]);
        if (c >= 0xD800 && c < 0xDC00) {
            c = 0x10000 + ((c - 0xD800) << 10) + (static_cast<unsigned long>(wide[++i]) - 0xDC00);
        }
        if (c >= ' ' && c <= '~' && c != '\\') {
            text += static_cast<char>(c);
        } else if (c < 0x100) {
            text += std::format("\\x{:02x}", c);
        } else if (c < 0x10000) {
            text += std::format("\\u{:04x}", c);
        } else {
            text += std::format("\\U{:08x}", c);
        }
    }
    return text;
}

struct VerifyArgs {
    std::string_view folder;
    std::string_view key_file;
};

// `<folder> --public-key <pem file>`, the two in either order, each once and
// not empty; nullopt for anything else. --public-key takes the word after it,
// whatever that word is.
std::optional<VerifyArgs> parse_verify_args(std::span<const std::string_view> args)
{
    std::optional<std::string_view> folder;
    std::optional<std::string_view> key_file;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--public-key") {
            if (key_file || i + 1 == args.size()) {
                return std::nullopt;
            }
            key_file = args[++i];
        } else {
            if (folder) {
                return std::nullopt;
            }
            folder = args[i];
        }
    }
    if (!folder || folder->empty() || !key_file || key_file->empty()) {
        return std::nullopt;
    }
    return VerifyArgs{*folder, *key_file};
}

// `rpworker signer verify <folder> --public-key <pem file>`. The key comes
// from the caller's file, never from the folder; the verdict is the Signer's.
int run_verify(const VerifyArgs& args, std::ostream& out, std::ostream& err)
{
    const std::optional<std::filesystem::path> key_path = path_from_utf8(args.key_file);
    if (!key_path) {
        err << "signer error: the --public-key path is not valid UTF-8\n";
        return exit_code::config;
    }
    const FileRead pem = read_whole_file(*key_path, kMaxPublicKeyFileBytes);
    if (pem.state != FileState::read) {
        err << "signer error: --public-key " << args.key_file << ": the file can't be read\n";
        return exit_code::config;
    }
    const std::optional<PublicKey> key = PublicKey::from_pem(pem.bytes);
    if (!key) {
        err << "signer error: --public-key " << args.key_file
            << ": not an Ed25519 public key in PEM\n";
        return exit_code::config;
    }
    const std::optional<std::filesystem::path> folder = path_from_utf8(args.folder);
    if (!folder) {
        err << "signer error: the folder's path is not valid UTF-8\n";
        return exit_code::config;
    }
    const std::optional<std::vector<std::string>> names = list_folder(*folder);
    if (!names) {
        err << "signer error: " << args.folder << ": the folder can't be opened\n";
        return exit_code::config;
    }

    const Verification verdict = Signer::verify_folder(folder_reader(*folder), *names, *key);
    if (verdict.word != VerifyWord::verified) {
        out << "not verified: " << to_string(verdict.word) << '\n';
        return answered(out, err, exit_code::restore);
    }
    for (const std::string& name : verdict.notes) {
        err << "note: not listed in the result: " << printable(name) << '\n';
    }
    out << "verified " << verdict.bundle_sha256 << " key " << verdict.key_id << '\n';
    return answered(out, err, exit_code::ok);
}

} // namespace

SignerCommandEnv default_signer_command_env()
{
    return {load_secrets_from_env};
}

int run_signer_command(std::span<const std::string_view> args, std::ostream& out,
                       std::ostream& err, const SignerCommandEnv& env)
{
    if (args.size() == 1 && args[0] == "public-key") {
        return run_public_key(out, err, env);
    }
    if (!args.empty() && args[0] == "verify") {
        const std::optional<VerifyArgs> parsed = parse_verify_args(args.subspan(1));
        if (parsed) {
            return run_verify(*parsed, out, err);
        }
    }
    err << kCliUsage;
    return exit_code::usage;
}

} // namespace rp
