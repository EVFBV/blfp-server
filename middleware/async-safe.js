/**
 * 异步路由安全包装
 * Express 4 不捕获 async 处理器抛出的异常，会变成"未处理的 Promise 拒绝"，
 * Node 15+ 默认直接终止进程（整个服务器掉线）。包一层 catch 交给错误中间件。
 */
function wrapAsyncHandler(handle) {
  if (typeof handle !== 'function' || handle.__asyncSafe) return handle;
  const wrapped = function (req, res, next) {
    try {
      const result = handle.call(this, req, res, next);
      if (result && typeof result.then === 'function') result.catch(next);
      return result;
    } catch (error) {
      next(error);
    }
  };
  wrapped.__asyncSafe = true;
  return wrapped;
}

function makeAsyncSafe(target) {
  try {
    const stack = (target && target.stack) || [];
    stack.forEach((layer) => {
      if (layer.route && Array.isArray(layer.route.stack)) {
        layer.route.stack.forEach((s) => { s.handle = wrapAsyncHandler(s.handle); });
      } else if (typeof layer.handle === 'function') {
        layer.handle = wrapAsyncHandler(layer.handle);
      }
    });
  } catch (e) {
    console.error('[Server] 路由异步包装失败:', e && e.message);
  }
  return target;
}

module.exports = { wrapAsyncHandler, makeAsyncSafe };
