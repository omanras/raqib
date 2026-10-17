// Resolve hook for child processes in tests: Node 22 strips TypeScript types
// natively, but the sources import "./x.js" for "./x.ts" (NodeNext style).
// This maps a relative .js specifier that does not exist to its .ts file.
export async function resolve(specifier, context, next) {
  try {
    return await next(specifier, context);
  } catch (err) {
    if (specifier.endsWith('.js') && (specifier.startsWith('./') || specifier.startsWith('../'))) {
      return next(`${specifier.slice(0, -3)}.ts`, context);
    }
    throw err;
  }
}
