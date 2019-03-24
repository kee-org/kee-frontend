export function _heap_init(heap, heapSize) {
    const size = heap ? heap.byteLength : heapSize || 65536;
    if (size & 0xfff || size <= 0)
        throw new Error('heap size must be a positive integer and a multiple of 4096');
    heap = heap || new Uint8Array(new ArrayBuffer(size));
    return heap;
}
export function _heap_write(heap, hpos, data, dpos, dlen) {
    const hlen = heap.length - hpos;
    const wlen = hlen < dlen ? hlen : dlen;
    heap.set(data.subarray(dpos, dpos + wlen), hpos);
    return wlen;
}

