/** @module
 *
 * 简单 token 认证, 适用于 deno/fresh.
 * Simple authentication with token for deno/fresh.
 */

import { join } from "@std/path";
import { dirname } from "@std/path/dirname";
import { timingSafeEqual } from "@std/crypto";
import { encodeBase64 } from "@std/encoding/base64";

/**
 * env var name
 */
export const ENV_XDG_RUNTIME_DIR = "XDG_RUNTIME_DIR";

async function get_random_data(): Promise<string> {
  // 64 Byte, 512bit random data
  const a = new Uint8Array(64);
  crypto.getRandomValues(a);

  // base64(sha256())
  const h = await crypto.subtle.digest("SHA-256", a);
  return encodeBase64(h);
}

function get_token_file_path(fp_token: string): string {
  const dir = Deno.env.get(ENV_XDG_RUNTIME_DIR)!;
  return join(dir, fp_token);
}

/**
 * 用于 token 认证.
 * token auth.
 */
export class AuthToken {
  // token save in memory
  private _token: Uint8Array;

  // log output
  private _logi: (t: string) => void;
  // token file path
  private _fp_token: string;
  // get token file path
  private _token_file_path: (fp_token: string) => string;

  /**
   * create the instance.
   *
   * @param fp_token token file path
   * @param logi log output
   * @param token_file_path get token file path
   */
  constructor(
    fp_token: string,
    logi: (t: string) => void = () => {},
    token_file_path: (fp_token: string) => string = get_token_file_path,
  ) {
    this._token = new Uint8Array();

    this._fp_token = fp_token;
    this._logi = logi;
    this._token_file_path = token_file_path;
  }

  /**
   * 初始化口令.
   * init token (and create token file).
   */
  async init() {
    const token_file = this._token_file_path(this._fp_token);
    this._logi(" token: " + token_file);

    const token = await get_random_data();
    // save token in file
    this._token = new TextEncoder().encode(token);

    // create parent dir
    await Deno.mkdir(dirname(token_file), { recursive: true });

    await Deno.writeTextFile(token_file, token);
  }

  /**
   * 检查口令.
   * check token.
   *
   * @param t token to check
   * @returns true: check pass
   */
  check(t: string): boolean {
    const d = new TextEncoder().encode(t);
    return timingSafeEqual(d, this._token);
  }
}
