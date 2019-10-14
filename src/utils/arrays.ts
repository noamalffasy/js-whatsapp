export function concatIntArray(...arrs: Uint8Array[]) {
  if (arrs.length > 0) {
    let finalArr = arrs[0];

    for (let i = 1; i < arrs.length; i++) {
      const arr = arrs[i];
      const tmp = new Uint8Array(finalArr.length + arr.length);

      tmp.set(finalArr, 0);
      tmp.set(arr, finalArr.length);

      finalArr = tmp;
    }

    return finalArr;
  }

  return new Uint8Array();
}

export function arraysEqual(arr1: Uint8Array, arr2: Uint8Array) {
  if (arr1 === arr2) return true;
  if (arr1 === null || arr2 === null) return false;
  if (arr1.length !== arr2.length) return false;

  for (let i = 0; i < arr1.length; i++) {
    if (arr1[i] !== arr2[i]) return false;
  }
  return true;
}
