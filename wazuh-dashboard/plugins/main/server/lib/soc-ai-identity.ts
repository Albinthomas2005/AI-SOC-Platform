/** Map authenticated Dashboard identities to SOC database identities via server config. */
export function socAiUsername(authenticatedUsername: string): string | undefined {
  const username = authenticatedUsername.trim();
  if (!username || username.length > 128) return undefined;

  const rawMap = process.env.SOC_AI_USERNAME_MAP?.trim();
  if (!rawMap) return username;
  try {
    const map = JSON.parse(rawMap);
    if (!map || typeof map !== 'object' || Array.isArray(map)) return undefined;
    const mapped = map[username];
    if (mapped === undefined) return username;
    return typeof mapped === 'string' && mapped.trim() && mapped.trim().length <= 128
      ? mapped.trim()
      : undefined;
  } catch {
    return undefined;
  }
}
