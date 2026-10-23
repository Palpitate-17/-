import { handle } from './scan-core.mjs';

export default { fetch(request, env) { return handle(request, env); } };
