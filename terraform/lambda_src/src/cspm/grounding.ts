type DocParam = { name?: string; default: string };

export function findUngroundedParam(
  params: Record<string, string[]>,
  docParams: DocParam[],
  findingJson: string,
): string | null {
  for (const [name, values] of Object.entries(params)) {
    const doc = docParams.find((p) => p.name === name);
    if (!doc) return name;
    for (const v of values) {
      if (findingJson.includes(v) || v === doc.default || /^(true|false|\d+)$/i.test(v)) continue;
      return name;
    }
  }
  return null;
}
