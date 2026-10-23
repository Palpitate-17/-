import { handle } from '../../scan-core.mjs';

export function onRequest(context) {
  return handle(context.request, context.env);
}
