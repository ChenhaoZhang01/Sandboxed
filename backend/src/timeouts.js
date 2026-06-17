export async function runWithTimeout(promise, timeoutMs, fallbackValue) {
  let settled = false;

  const timeout = new Promise((resolve) => {
    const id = setTimeout(() => {
      settled = true;
      resolve(fallbackValue);
    }, timeoutMs);

    Promise.resolve(promise).finally(() => {
      clearTimeout(id);
      if (!settled) {
        settled = true;
      }
    });
  });

  return Promise.race([promise, timeout]);
}
