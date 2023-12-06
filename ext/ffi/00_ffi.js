// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

const core = globalThis.Deno.core;
const {
  op_ffi_buf_copy_into,
  op_ffi_call_ptr,
  op_ffi_create_token,
  op_ffi_cstr_read,
  op_ffi_get_buf,
  op_ffi_get_static,
  op_ffi_load,
  op_ffi_ptr_create,
  op_ffi_ptr_equals,
  op_ffi_ptr_of_exact,
  op_ffi_ptr_of,
  op_ffi_ptr_offset,
  op_ffi_ptr_value,
  op_ffi_read_bool,
  op_ffi_read_f32,
  op_ffi_read_f64,
  op_ffi_read_i16,
  op_ffi_read_i32,
  op_ffi_read_i64,
  op_ffi_read_i8,
  op_ffi_read_ptr,
  op_ffi_read_u16,
  op_ffi_read_u32,
  op_ffi_read_u64,
  op_ffi_read_u8,
  op_ffi_token_buf_copy_into,
  op_ffi_token_call_ptr,
  op_ffi_token_close,
  op_ffi_token_cstr_read,
  op_ffi_token_get_buf,
  op_ffi_token_ptr_create,
  op_ffi_token_ptr_equals,
  op_ffi_token_ptr_of_exact,
  op_ffi_token_ptr_of,
  op_ffi_token_ptr_offset,
  op_ffi_token_ptr_value,
  op_ffi_token_read_bool,
  op_ffi_token_read_f32,
  op_ffi_token_read_f64,
  op_ffi_token_read_i16,
  op_ffi_token_read_i32,
  op_ffi_token_read_i64,
  op_ffi_token_read_i8,
  op_ffi_token_read_ptr,
  op_ffi_token_read_u16,
  op_ffi_token_read_u32,
  op_ffi_token_read_u64,
  op_ffi_token_read_u8,
  op_ffi_token_unsafe_callback_create,
  op_ffi_token_write_bool,
  op_ffi_token_write_f32,
  op_ffi_token_write_f64,
  op_ffi_token_write_i16,
  op_ffi_token_write_i32,
  op_ffi_token_write_i64,
  op_ffi_token_write_i8,
  op_ffi_token_write_ptr,
  op_ffi_token_write_u16,
  op_ffi_token_write_u32,
  op_ffi_token_write_u64,
  op_ffi_token_write_u8,
  op_ffi_unsafe_callback_close,
  op_ffi_unsafe_callback_create,
} = core.ops;
const primordials = globalThis.__bootstrap.primordials;
const {
  ArrayBufferIsView,
  ArrayBufferPrototype,
  ArrayBufferPrototypeGetByteLength,
  ArrayPrototypeMap,
  ArrayPrototypeJoin,
  DataViewPrototypeGetByteLength,
  ObjectDefineProperty,
  ObjectFreeze,
  ObjectHasOwn,
  ObjectPrototypeIsPrototypeOf,
  ObjectSeal,
  ObjectSetPrototypeOf,
  Number,
  NumberIsSafeInteger,
  TypedArrayPrototypeGetBuffer,
  TypedArrayPrototypeGetByteLength,
  TypedArrayPrototypeGetSymbolToStringTag,
  TypeError,
  Uint8Array,
  Int32Array,
  Uint32Array,
  BigInt64Array,
  BigUint64Array,
  Function,
  ReflectHas,
  PromisePrototypeThen,
  MathMax,
  MathCeil,
  SafeMap,
  SafeArrayIterator,
  SafeWeakMap,
} = primordials;
import { pathFromURL } from "ext:deno_web/00_infra.js";

/**
 * @param {BufferSource} source
 * @returns {number}
 */
function getBufferSourceByteLength(source) {
  if (ArrayBufferIsView(source)) {
    if (TypedArrayPrototypeGetSymbolToStringTag(source) !== undefined) {
      // TypedArray
      return TypedArrayPrototypeGetByteLength(source);
    } else {
      // DataView
      return DataViewPrototypeGetByteLength(source);
    }
  }
  return ArrayBufferPrototypeGetByteLength(source);
}
const U32_BUFFER = new Uint32Array(2);
const U64_BUFFER = new BigUint64Array(TypedArrayPrototypeGetBuffer(U32_BUFFER));
const I64_BUFFER = new BigInt64Array(TypedArrayPrototypeGetBuffer(U32_BUFFER));
class UnsafePointerView {
  pointer;

  constructor(pointer) {
    this.pointer = pointer;
  }

  getBool(offset = 0) {
    return op_ffi_read_bool(
      this.pointer,
      offset,
    );
  }

  getUint8(offset = 0) {
    return op_ffi_read_u8(
      this.pointer,
      offset,
    );
  }

  getInt8(offset = 0) {
    return op_ffi_read_i8(
      this.pointer,
      offset,
    );
  }

  getUint16(offset = 0) {
    return op_ffi_read_u16(
      this.pointer,
      offset,
    );
  }

  getInt16(offset = 0) {
    return op_ffi_read_i16(
      this.pointer,
      offset,
    );
  }

  getUint32(offset = 0) {
    return op_ffi_read_u32(
      this.pointer,
      offset,
    );
  }

  getInt32(offset = 0) {
    return op_ffi_read_i32(
      this.pointer,
      offset,
    );
  }

  getBigUint64(offset = 0) {
    op_ffi_read_u64(
      this.pointer,
      offset,
      U32_BUFFER,
    );
    return U64_BUFFER[0];
  }

  getBigInt64(offset = 0) {
    op_ffi_read_i64(
      this.pointer,
      offset,
      U32_BUFFER,
    );
    return I64_BUFFER[0];
  }

  getFloat32(offset = 0) {
    return op_ffi_read_f32(
      this.pointer,
      offset,
    );
  }

  getFloat64(offset = 0) {
    return op_ffi_read_f64(
      this.pointer,
      offset,
    );
  }

  getPointer(offset = 0) {
    return op_ffi_read_ptr(
      this.pointer,
      offset,
    );
  }

  getCString(offset = 0) {
    return op_ffi_cstr_read(
      this.pointer,
      offset,
    );
  }

  static getCString(pointer, offset = 0) {
    return op_ffi_cstr_read(
      pointer,
      offset,
    );
  }

  getArrayBuffer(byteLength, offset = 0) {
    return op_ffi_get_buf(
      this.pointer,
      offset,
      byteLength,
    );
  }

  static getArrayBuffer(pointer, byteLength, offset = 0) {
    return op_ffi_get_buf(
      pointer,
      offset,
      byteLength,
    );
  }

  copyInto(destination, offset = 0) {
    op_ffi_buf_copy_into(
      this.pointer,
      offset,
      destination,
      getBufferSourceByteLength(destination),
    );
  }

  static copyInto(pointer, destination, offset = 0) {
    op_ffi_buf_copy_into(
      pointer,
      offset,
      destination,
      getBufferSourceByteLength(destination),
    );
  }
}

const OUT_BUFFER = new Uint32Array(2);
const OUT_BUFFER_64 = new BigInt64Array(
  TypedArrayPrototypeGetBuffer(OUT_BUFFER),
);
const POINTER_TO_BUFFER_WEAK_MAP = new SafeWeakMap();
class UnsafePointer {
  static create(value) {
    return op_ffi_ptr_create(value);
  }

  static equals(a, b) {
    if (a === null || b === null) {
      return a === b;
    }
    return op_ffi_ptr_equals(a, b);
  }

  static of(value) {
    if (ObjectPrototypeIsPrototypeOf(UnsafeCallbackPrototype, value)) {
      return value.pointer;
    }
    let pointer;
    if (ArrayBufferIsView(value)) {
      if (value.length === 0) {
        pointer = op_ffi_ptr_of_exact(value);
      } else {
        pointer = op_ffi_ptr_of(value);
      }
    } else if (ObjectPrototypeIsPrototypeOf(ArrayBufferPrototype, value)) {
      if (value.length === 0) {
        pointer = op_ffi_ptr_of_exact(new Uint8Array(value));
      } else {
        pointer = op_ffi_ptr_of(new Uint8Array(value));
      }
    } else {
      throw new TypeError(
        "Expected ArrayBuffer, ArrayBufferView or UnsafeCallbackPrototype",
      );
    }
    if (pointer) {
      POINTER_TO_BUFFER_WEAK_MAP.set(pointer, value);
    }
    return pointer;
  }

  static offset(value, offset) {
    return op_ffi_ptr_offset(value, offset);
  }

  static value(value) {
    if (ObjectPrototypeIsPrototypeOf(UnsafeCallbackPrototype, value)) {
      value = value.pointer;
    }
    op_ffi_ptr_value(value, OUT_BUFFER);
    const result = OUT_BUFFER[0] + 2 ** 32 * OUT_BUFFER[1];
    if (NumberIsSafeInteger(result)) {
      return result;
    }
    return OUT_BUFFER_64[0];
  }
}

class UnsafeFnPointer {
  pointer;
  definition;
  #structSize;

  constructor(pointer, definition) {
    this.pointer = pointer;
    this.definition = definition;
    this.#structSize = isStruct(definition.result)
      ? getTypeSizeAndAlignment(definition.result)[0]
      : null;
  }

  call(...parameters) {
    if (this.definition.nonblocking) {
      if (this.#structSize === null) {
        return core.opAsync(
          "op_ffi_call_ptr_nonblocking",
          this.pointer,
          this.definition,
          parameters,
        );
      } else {
        const buffer = new Uint8Array(this.#structSize);
        return PromisePrototypeThen(
          core.opAsync(
            "op_ffi_call_ptr_nonblocking",
            this.pointer,
            this.definition,
            parameters,
            buffer,
          ),
          () => buffer,
        );
      }
    } else {
      if (this.#structSize === null) {
        return op_ffi_call_ptr(
          this.pointer,
          this.definition,
          parameters,
        );
      } else {
        const buffer = new Uint8Array(this.#structSize);
        op_ffi_call_ptr(
          this.pointer,
          this.definition,
          parameters,
          buffer,
        );
        return buffer;
      }
    }
  }
}

function isReturnedAsBigInt(type) {
  return type === "u64" || type === "i64" ||
    type === "usize" || type === "isize";
}

function isI64(type) {
  return type === "i64" || type === "isize";
}

function isStruct(type) {
  return typeof type === "object" && type !== null &&
    typeof type.struct === "object";
}

function getTypeSizeAndAlignment(type, cache = new SafeMap()) {
  if (isStruct(type)) {
    const cached = cache.get(type);
    if (cached !== undefined) {
      if (cached === null) {
        throw new TypeError("Recursive struct definition");
      }
      return cached;
    }
    cache.set(type, null);
    let size = 0;
    let alignment = 1;
    for (const field of new SafeArrayIterator(type.struct)) {
      const { 0: fieldSize, 1: fieldAlign } = getTypeSizeAndAlignment(
        field,
        cache,
      );
      alignment = MathMax(alignment, fieldAlign);
      size = MathCeil(size / fieldAlign) * fieldAlign;
      size += fieldSize;
    }
    size = MathCeil(size / alignment) * alignment;
    const result = [size, alignment];
    cache.set(type, result);
    return result;
  }

  switch (type) {
    case "bool":
    case "u8":
    case "i8":
      return [1, 1];
    case "u16":
    case "i16":
      return [2, 2];
    case "u32":
    case "i32":
    case "f32":
      return [4, 4];
    case "u64":
    case "i64":
    case "f64":
    case "pointer":
    case "buffer":
    case "function":
    case "usize":
    case "isize":
      return [8, 8];
    default:
      throw new TypeError(`Unsupported type: ${type}`);
  }
}

class UnsafeCallback {
  #refcount;
  // Internal promise only meant to keep Deno from exiting
  #refpromise;
  #rid;
  definition;
  callback;
  pointer;

  constructor(definition, callback) {
    if (definition.nonblocking) {
      throw new TypeError(
        "Invalid UnsafeCallback, cannot be nonblocking",
      );
    }
    const { 0: rid, 1: pointer } = op_ffi_unsafe_callback_create(
      definition,
      callback,
    );
    this.#refcount = 0;
    this.#rid = rid;
    this.pointer = pointer;
    this.definition = definition;
    this.callback = callback;
  }

  static threadSafe(definition, callback) {
    const unsafeCallback = new UnsafeCallback(definition, callback);
    unsafeCallback.ref();
    return unsafeCallback;
  }

  ref() {
    if (this.#refcount++ === 0) {
      if (this.#refpromise) {
        // Re-refing
        core.refOpPromise(this.#refpromise);
      } else {
        this.#refpromise = core.opAsync(
          "op_ffi_unsafe_callback_ref",
          this.#rid,
        );
      }
    }
    return this.#refcount;
  }

  unref() {
    // Only decrement refcount if it is positive, and only
    // unref the callback if refcount reaches zero.
    if (this.#refcount > 0 && --this.#refcount === 0) {
      core.unrefOpPromise(this.#refpromise);
    }
    return this.#refcount;
  }

  close() {
    this.#refcount = 0;
    op_ffi_unsafe_callback_close(this.#rid);
  }
}

const UnsafeCallbackPrototype = UnsafeCallback.prototype;

const createFfiToken = (path) => {
  const token = op_ffi_create_token(path);
  const tokenInUse = {
    status: true,
  };
  const assertTokenIsUsable = () => {
    if (tokenInUse.status === false) {
      throw new TypeError("Cannot use closed FFI Token");
    }
  };
  class TokenizedPointer {
    static {
      ObjectSetPrototypeOf(this, null);
      ObjectSetPrototypeOf(this.prototype, null);
      delete this.prototype.constructor;
      ObjectSetPrototypeOf(this.equals, null);
      ObjectFreeze(this.equals);
      ObjectSetPrototypeOf(this.create, null);
      ObjectFreeze(this.create);
      ObjectSetPrototypeOf(this.of, null);
      ObjectFreeze(this.of);
      ObjectSetPrototypeOf(this.offset, null);
      ObjectFreeze(this.offset);
      ObjectSetPrototypeOf(this.value, null);
      ObjectFreeze(this.value);
      ObjectFreeze(this.prototype);
      ObjectFreeze(this);
    }

    constructor() {
      throw new TypeError("TokenizedPointer is not a constructor");
    }

    static create(value) {
      assertTokenIsUsable();
      return op_ffi_token_ptr_create(token, value);
    }

    static equals(pointer, other) {
      assertTokenIsUsable();
      if (pointer === other) {
        return true;
      } else if (pointer === null || other === null) {
        return false;
      }
      return op_ffi_token_ptr_equals(token, pointer, other);
    }

    static of(buffer) {
      assertTokenIsUsable();
      let pointer;
      if (ArrayBufferIsView(buffer)) {
        if (buffer.length === 0) {
          pointer = op_ffi_token_ptr_of_exact(token, buffer);
        } else {
          pointer = op_ffi_token_ptr_of(token, buffer);
        }
      } else if (ObjectPrototypeIsPrototypeOf(ArrayBufferPrototype, buffer)) {
        if (buffer.length === 0) {
          pointer = op_ffi_token_ptr_of_exact(
            token,
            new Uint8Array(buffer),
          );
        } else {
          pointer = op_ffi_token_ptr_of(token, new Uint8Array(buffer));
        }
      } else {
        throw new TypeError(
          "Expected ArrayBuffer, ArrayBufferView or UnsafeCallbackPrototype",
        );
      }
      if (pointer) {
        POINTER_TO_BUFFER_WEAK_MAP.set(pointer, buffer);
      }
      return pointer;
    }

    static offset(pointer, offset) {
      assertTokenIsUsable();
      return op_ffi_token_ptr_offset(token, pointer, offset);
    }

    static value(pointer) {
      assertTokenIsUsable();
      return op_ffi_token_ptr_value(token, pointer);
    }
  }

  class TokenizedPointerView {
    #ptr;

    static {
      ObjectSetPrototypeOf(this, null);
      ObjectSetPrototypeOf(this.prototype, null);
      delete this.prototype.constructor;
      ObjectSetPrototypeOf(this.prototype.getBool, null);
      ObjectFreeze(this.prototype.getBool);
      ObjectSetPrototypeOf(this.prototype.getUint8, null);
      ObjectFreeze(this.prototype.getUint8);
      ObjectSetPrototypeOf(this.prototype.getInt8, null);
      ObjectFreeze(this.prototype.getInt8);
      ObjectSetPrototypeOf(this.prototype.getUint16, null);
      ObjectFreeze(this.prototype.getUint16);
      ObjectSetPrototypeOf(this.prototype.getInt16, null);
      ObjectFreeze(this.prototype.getInt16);
      ObjectSetPrototypeOf(this.prototype.getUint32, null);
      ObjectFreeze(this.prototype.getUint32);
      ObjectSetPrototypeOf(this.prototype.getInt32, null);
      ObjectFreeze(this.prototype.getInt32);
      ObjectSetPrototypeOf(this.prototype.getBigUint64, null);
      ObjectFreeze(this.prototype.getBigUint64);
      ObjectSetPrototypeOf(this.prototype.getBigInt64, null);
      ObjectFreeze(this.prototype.getBigInt64);
      ObjectSetPrototypeOf(this.prototype.getFloat32, null);
      ObjectFreeze(this.prototype.getFloat32);
      ObjectSetPrototypeOf(this.prototype.getFloat64, null);
      ObjectFreeze(this.prototype.getFloat64);
      ObjectSetPrototypeOf(this.prototype.getPointer, null);
      ObjectFreeze(this.prototype.getPointer);
      ObjectSetPrototypeOf(this.prototype.setBool, null);
      ObjectFreeze(this.prototype.setBool);
      ObjectSetPrototypeOf(this.prototype.setUint8, null);
      ObjectFreeze(this.prototype.setUint8);
      ObjectSetPrototypeOf(this.prototype.setInt8, null);
      ObjectFreeze(this.prototype.setInt8);
      ObjectSetPrototypeOf(this.prototype.setUint16, null);
      ObjectFreeze(this.prototype.setUint16);
      ObjectSetPrototypeOf(this.prototype.setInt16, null);
      ObjectFreeze(this.prototype.setInt16);
      ObjectSetPrototypeOf(this.prototype.setUint32, null);
      ObjectFreeze(this.prototype.setUint32);
      ObjectSetPrototypeOf(this.prototype.setInt32, null);
      ObjectFreeze(this.prototype.setInt32);
      ObjectSetPrototypeOf(this.prototype.setBigUint64, null);
      ObjectFreeze(this.prototype.setBigUint64);
      ObjectSetPrototypeOf(this.prototype.setBigInt64, null);
      ObjectFreeze(this.prototype.setBigInt64);
      ObjectSetPrototypeOf(this.prototype.setFloat32, null);
      ObjectFreeze(this.prototype.setFloat32);
      ObjectSetPrototypeOf(this.prototype.setFloat64, null);
      ObjectFreeze(this.prototype.setFloat64);
      ObjectSetPrototypeOf(this.prototype.setPointer, null);
      ObjectFreeze(this.prototype.setPointer);
      ObjectSetPrototypeOf(this.prototype.getCString, null);
      ObjectFreeze(this.prototype.getCString);
      ObjectSetPrototypeOf(this.prototype.getArrayBuffer, null);
      ObjectFreeze(this.prototype.getArrayBuffer);
      ObjectSetPrototypeOf(this.prototype.copyInto, null);
      ObjectFreeze(this.prototype.copyInto);
      ObjectSetPrototypeOf(this.getCString, null);
      ObjectFreeze(this.getCString);
      ObjectSetPrototypeOf(this.getArrayBuffer, null);
      ObjectFreeze(this.getArrayBuffer);
      ObjectSetPrototypeOf(this.copyInto, null);
      ObjectFreeze(this.copyInto);
      ObjectFreeze(this.prototype);
      ObjectFreeze(this);
    }

    constructor(ptr) {
      assertTokenIsUsable();
      this.#ptr = ptr;
      ObjectFreeze(this);
    }

    getBool(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_read_bool(
        token,
        this.#ptr,
        offset,
      );
    }

    getUint8(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_read_u8(
        token,
        this.#ptr,
        offset,
      );
    }

    getInt8(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_read_i8(
        token,
        this.#ptr,
        offset,
      );
    }

    getUint16(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_read_u16(
        token,
        this.#ptr,
        offset,
      );
    }

    getInt16(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_read_i16(
        token,
        this.#ptr,
        offset,
      );
    }

    getUint32(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_read_u32(
        token,
        this.#ptr,
        offset,
      );
    }

    getInt32(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_read_i32(
        token,
        this.#ptr,
        offset,
      );
    }

    getBigUint64(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_read_u64(
        token,
        this.#ptr,
        offset,
      );
    }

    getBigInt64(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_read_i64(
        token,
        this.#ptr,
        offset,
      );
    }

    getFloat32(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_read_f32(
        token,
        this.#ptr,
        offset,
      );
    }

    getFloat64(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_read_f64(
        token,
        this.#ptr,
        offset,
      );
    }

    getPointer(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_read_ptr(
        token,
        this.#ptr,
        offset,
      );
    }

    setBool(value, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_write_bool(
        token,
        this.#ptr,
        offset,
        value,
      );
    }

    setUint8(value, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_write_u8(
        token,
        this.#ptr,
        offset,
        value,
      );
    }

    setInt8(value, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_write_i8(
        token,
        this.#ptr,
        offset,
        value,
      );
    }

    setUint16(value, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_write_u16(
        token,
        this.#ptr,
        offset,
        value,
      );
    }

    setInt16(value, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_write_i16(
        token,
        this.#ptr,
        offset,
        value,
      );
    }

    setUint32(value, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_write_u32(
        token,
        this.#ptr,
        offset,
        value,
      );
    }

    setInt32(value, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_write_i32(
        token,
        this.#ptr,
        offset,
        value,
      );
    }

    setBigUint64(value, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_write_u64(
        token,
        this.#ptr,
        offset,
        value,
      );
    }

    setBigInt64(value, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_write_i64(
        token,
        this.#ptr,
        offset,
        value,
      );
    }

    setFloat32(value, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_write_f32(
        token,
        this.#ptr,
        offset,
        value,
      );
    }

    setFloat64(value, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_write_f64(
        token,
        this.#ptr,
        offset,
        value,
      );
    }

    setPointer(value, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_write_ptr(
        token,
        this.#ptr,
        offset,
        value,
      );
    }

    getCString(offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_cstr_read(
        token,
        this.#ptr,
        offset,
      );
    }

    getArrayBuffer(byteLength, offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_get_buf(
        token,
        this.#ptr,
        offset,
        byteLength,
      );
    }

    copyInto(destination, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_buf_copy_into(
        token,
        this.#ptr,
        offset,
        destination,
        getBufferSourceByteLength(destination),
      );
    }

    static getCString(pointer, offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_cstr_read(
        token,
        pointer,
        offset,
      );
    }

    static getArrayBuffer(pointer, byteLength, offset = 0) {
      assertTokenIsUsable();
      return op_ffi_token_get_buf(
        token,
        pointer,
        offset,
        byteLength,
      );
    }

    static copyInto(pointer, destination, offset = 0) {
      assertTokenIsUsable();
      op_ffi_token_buf_copy_into(
        token,
        pointer,
        offset,
        destination,
        getBufferSourceByteLength(destination),
      );
    }
  }

  class TokenizedCallback {
    #refcount;
    // Internal promise only meant to keep Deno from exiting
    #refpromise;
    #rid;
    #pointer;

    static {
      ObjectSetPrototypeOf(this, null);
      ObjectSetPrototypeOf(this.prototype, null);
      delete this.prototype.constructor;
      ObjectSetPrototypeOf(this.prototype.ref, null);
      ObjectFreeze(this.prototype.ref);
      ObjectSetPrototypeOf(this.prototype.unref, null);
      ObjectFreeze(this.prototype.unref);
      ObjectSetPrototypeOf(this.prototype.close, null);
      ObjectFreeze(this.prototype.close);
      ObjectSetPrototypeOf(this.threadSafe, null);
      ObjectFreeze(this.threadSafe);
      ObjectFreeze(this.prototype);
      ObjectFreeze(this);
    }

    constructor(definition, callback) {
      assertTokenIsUsable();
      if (definition.nonblocking) {
        throw new TypeError(
          "Invalid TokenizedCallback, cannot be nonblocking",
        );
      }
      const { 0: cbRid, 1: cbPointer } = op_ffi_token_unsafe_callback_create(
        token,
        definition,
        callback,
      );
      this.#refcount = 0;
      this.#rid = cbRid;
      this.#pointer = cbPointer;
      ObjectSeal(this);
    }

    get pointer() {
      return this.#pointer;
    }

    static threadSafe(definition, callback) {
      const unsafeCallback = new UnsafeCallback(definition, callback);
      unsafeCallback.ref();
      return unsafeCallback;
    }

    ref() {
      if (this.#refcount++ === 0) {
        if (this.#refpromise) {
          // Re-refing
          core.refOpPromise(this.#refpromise);
        } else {
          assertTokenIsUsable();
          this.#refpromise = core.opAsync(
            "op_ffi_unsafe_callback_ref",
            this.#rid,
          );
        }
      }
      return this.#refcount;
    }

    unref() {
      // Only decrement refcount if it is positive, and only
      // unref the callback if refcount reaches zero.
      if (this.#refcount > 0 && --this.#refcount === 0) {
        core.unrefOpPromise(this.#refpromise);
      }
      return this.#refcount;
    }

    close() {
      this.#refcount = 0;
      op_ffi_unsafe_callback_close(this.#rid);
      this.#pointer = null;
    }
  }

  class TokenizedFnPointer {
    #pointer;
    #definition;
    #structSize;

    static {
      ObjectSetPrototypeOf(this, null);
      ObjectSetPrototypeOf(this.prototype, null);
      delete this.prototype.constructor;
      ObjectSetPrototypeOf(this.prototype.call, null);
      ObjectFreeze(this.prototype.call);
      ObjectFreeze(this.prototype);
      ObjectFreeze(this);
    }

    constructor(pointer, definition) {
      assertTokenIsUsable();
      this.#pointer = pointer;
      this.#definition = definition;
      this.#structSize = isStruct(definition.result)
        ? getTypeSizeAndAlignment(definition.result)[0]
        : null;
      ObjectFreeze(this);
    }

    call(...parameters) {
      assertTokenIsUsable();
      if (this.#definition.nonblocking) {
        if (this.#structSize === null) {
          return core.opAsync(
            "op_ffi_token_call_ptr_nonblocking",
            token,
            this.#pointer,
            this.#definition,
            parameters,
          );
        } else {
          const buffer = new Uint8Array(this.#structSize);
          return PromisePrototypeThen(
            core.opAsync(
              "op_ffi_token_call_ptr_nonblocking",
              token,
              this.#pointer,
              this.#definition,
              parameters,
              buffer,
            ),
            () => buffer,
          );
        }
      } else {
        if (this.#structSize === null) {
          return op_ffi_token_call_ptr(
            token,
            this.#pointer,
            this.#definition,
            parameters,
          );
        } else {
          const buffer = new Uint8Array(this.#structSize);
          op_ffi_token_call_ptr(
            token,
            this.#pointer,
            this.#definition,
            parameters,
            buffer,
          );
          return buffer;
        }
      }
    }
  }

  const close = () => {
    if (tokenInUse.status === false) {
      return;
    }
    op_ffi_token_close(token);
    tokenInUse.status = false;
  };
  ObjectSetPrototypeOf(close, null);
  ObjectFreeze(close);

  return {
    close,
    TokenizedCallback,
    TokenizedFnPointer,
    TokenizedPointer,
    TokenizedPointerView,
  };
};

class DynamicLibrary {
  #rid;
  symbols = {};

  constructor(path, symbols) {
    ({ 0: this.#rid, 1: this.symbols } = op_ffi_load({ path, symbols }));
    for (const symbol in symbols) {
      if (!ObjectHasOwn(symbols, symbol)) {
        continue;
      }

      // Symbol was marked as optional, and not found.
      // In that case, we set its value to null in Rust-side.
      if (symbols[symbol] === null) {
        continue;
      }

      if (ReflectHas(symbols[symbol], "type")) {
        const type = symbols[symbol].type;
        if (type === "void") {
          throw new TypeError(
            "Foreign symbol of type 'void' is not supported.",
          );
        }

        const name = symbols[symbol].name || symbol;
        const value = op_ffi_get_static(
          this.#rid,
          name,
          type,
          symbols[symbol].optional,
        );
        ObjectDefineProperty(
          this.symbols,
          symbol,
          {
            configurable: false,
            enumerable: true,
            value,
            writable: false,
          },
        );
        continue;
      }
      const resultType = symbols[symbol].result;
      const isStructResult = isStruct(resultType);
      const structSize = isStructResult
        ? getTypeSizeAndAlignment(resultType)[0]
        : 0;
      const needsUnpacking = isReturnedAsBigInt(resultType);

      const isNonBlocking = symbols[symbol].nonblocking;
      if (isNonBlocking) {
        ObjectDefineProperty(
          this.symbols,
          symbol,
          {
            configurable: false,
            enumerable: true,
            value: (...parameters) => {
              if (isStructResult) {
                const buffer = new Uint8Array(structSize);
                const ret = core.opAsync(
                  "op_ffi_call_nonblocking",
                  this.#rid,
                  symbol,
                  parameters,
                  buffer,
                );
                return PromisePrototypeThen(
                  ret,
                  () => buffer,
                );
              } else {
                return core.opAsync(
                  "op_ffi_call_nonblocking",
                  this.#rid,
                  symbol,
                  parameters,
                );
              }
            },
            writable: false,
          },
        );
      }

      if (needsUnpacking && !isNonBlocking) {
        const call = this.symbols[symbol];
        const parameters = symbols[symbol].parameters;
        const vi = new Int32Array(2);
        const vui = new Uint32Array(TypedArrayPrototypeGetBuffer(vi));
        const b = new BigInt64Array(TypedArrayPrototypeGetBuffer(vi));

        const params = ArrayPrototypeJoin(
          ArrayPrototypeMap(parameters, (_, index) => `p${index}`),
          ", ",
        );
        // Make sure V8 has no excuse to not optimize this function.
        this.symbols[symbol] = new Function(
          "vi",
          "vui",
          "b",
          "call",
          "NumberIsSafeInteger",
          "Number",
          `return function (${params}) {
            call(${params}${parameters.length > 0 ? ", " : ""}vi);
            ${
            isI64(resultType)
              ? `const n1 = Number(b[0])`
              : `const n1 = vui[0] + 2 ** 32 * vui[1]` // Faster path for u64
          };
            if (NumberIsSafeInteger(n1)) return n1;
            return b[0];
          }`,
        )(vi, vui, b, call, NumberIsSafeInteger, Number);
      } else if (isStructResult && !isNonBlocking) {
        const call = this.symbols[symbol];
        const parameters = symbols[symbol].parameters;
        const params = ArrayPrototypeJoin(
          ArrayPrototypeMap(parameters, (_, index) => `p${index}`),
          ", ",
        );
        this.symbols[symbol] = new Function(
          "call",
          `return function (${params}) {
            const buffer = new Uint8Array(${structSize});
            call(${params}${parameters.length > 0 ? ", " : ""}buffer);
            return buffer;
          }`,
        )(call);
      }
    }
  }

  close() {
    core.close(this.#rid);
  }
}

function dlopen(path, symbols) {
  return new DynamicLibrary(pathFromURL(path), symbols);
}

export {
  createFfiToken,
  dlopen,
  UnsafeCallback,
  UnsafeFnPointer,
  UnsafePointer,
  UnsafePointerView,
};
