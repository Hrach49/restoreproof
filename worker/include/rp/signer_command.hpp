#pragma once

// `rpworker signer public-key` and `rpworker signer verify <folder>
// --public-key <pem file>` (W4.3, docs/decisions.md 2026-10-05, point 4): the
// Worker's public key for registration, and the C++ verifier over a run
// folder. Both only read. Every verdict is rp::Signer's (rp/signer.hpp); here
// are the arguments, the files and the lines.

#include <rp/secrets.hpp>

#include <cstdint>
#include <functional>
#include <iosfwd>
#include <span>
#include <string_view>

namespace rp {

// A --public-key file larger than this isn't read (a public key's PEM is 113
// bytes). verify_bundle.py has the same limit.
inline constexpr std::uintmax_t kMaxPublicKeyFileBytes = 64u * 1024u;

// What the commands reach outside themselves. run_cli passes
// default_signer_command_env(); tests pass their own secrets.
struct SignerCommandEnv {
    // rp::load_secrets_from_env. Called by `public-key` only, and only after
    // the arguments parsed: `verify` needs no secret and no config.
    std::function<Secrets()> load_secrets;
};

// The real environment: rp::load_secrets_from_env.
SignerCommandEnv default_signer_command_env();

// `rpworker signer ...`. `args` is what follows "signer" on the command line,
// in UTF-8. Returns an rp::exit_code; 64 with rp::kCliUsage on `err` for
// arguments it doesn't understand (another subcommand, a word too many, a
// missing or empty <folder>, --public-key or --tsa-ca value, any given twice).
//
// `public-key` prints to `out` the SubjectPublicKeyInfo PEM of the key in
// RP_SIGNING_KEY_BASE64 (three lines) and nothing else, so that `out` is a key
// file as it is: what is registered with the Cloud and handed to a verifier
// (`signer verify --public-key`, verify_bundle.py). Then, on `err`, the line
// `key <key_id>` (the W4.3 review moved it there: a verifier refuses a key
// file with a line after the block). Never the private key, whose text is
// wiped before anything is printed. Exit 1 with one line on
// `err`: "config error: <message>" for a ConfigError from `load_secrets`,
// "config error: RP_SIGNING_KEY_BASE64 is not set" and "config error:
// RP_SIGNING_KEY_BASE64 is not an Ed25519 private key (Base64 of PKCS#8 DER)".
//
// `verify <folder> --public-key <pem file> [--tsa-ca <pem file>]` (in any
// order) checks the run folder with Signer::verify_folder against the key in
// the file and, W4.4, its timestamp against the certificates of --tsa-ca
// (PEM, at most kMaxPublicKeyFileBytes; "signer error: --tsa-ca <file>: the
// file can't be read" / "... no certificate in PEM", exit 1), and prints one
// line to `out`:
//  - "verified <bundle_sha256> key <key_id> timestamp <time|none|unchecked>",
//    exit 0 (rp::timestamp_field); before it, on `err`, one
//    "note: not listed in the result: <name>" line per file of the folder that
//    is neither result.json, signature.json, timestamp.tst nor a listed
//    attachment (the name in ASCII, anything else as \xNN, \uNNNN or
//    \UNNNNNNNN, lower-case hex; a name that isn't valid UTF-16 is a note
//    like any other, its lone surrogate written \udXXX), then "note: not
//    timestamped" for a folder without timestamp.tst, or "note:
//    timestamp.tst was not checked: no --tsa-ca";
//  - "not verified: <word>", exit 5 (exit_code::restore), the word
//    rp::to_string(VerifyWord): anything wrong inside the folder, a missing
//    file included.
// The line on `out` is what shared/tools/verify_bundle.py prints for the same
// folder and key; the exit codes are each tool's own. Exit 1, one line on
// `err` and nothing on `out`, only when no answer could be made, the key file
// looked at first:
//  - "signer error: the --public-key path is not valid UTF-8";
//  - "signer error: --public-key <file>: the file can't be read" (not there, a
//    folder, or larger than kMaxPublicKeyFileBytes);
//  - "signer error: --public-key <file>: not an Ed25519 public key in PEM"
//    (the one rule for a key file: rp/ed25519.hpp, public_key_from_pem);
//  - "signer error: the folder's path is not valid UTF-8";
//  - "signer error: <folder>: the folder can't be opened";
//  - "signer error: the result couldn't be checked against its schema" (the
//    embedded validator couldn't be loaded or failed: rp::VerifierFailure).
// The folder is listed and read through rp::extended_folder (src/file_read.hpp),
// so a file past MAX_PATH is read like any other; a file is there only when
// the folder lists its name byte for byte.
//
// For both, an answer that didn't reach `out` isn't one: "signer error: the
// answer couldn't be written" and exit 1. No exception is caught here but a
// ConfigError from `load_secrets` and a VerifierFailure: what the reader, the
// primitive or a stream throws is run_cli's "error: unexpected failure", exit
// 1, never a verdict.
int run_signer_command(std::span<const std::string_view> args, std::ostream& out,
                       std::ostream& err, const SignerCommandEnv& env);

} // namespace rp
