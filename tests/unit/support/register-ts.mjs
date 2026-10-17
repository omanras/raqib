// node --import ./tests/unit/support/register-ts.mjs some.ts
import { register } from 'node:module';

register('./ts-resolve.mjs', import.meta.url);
