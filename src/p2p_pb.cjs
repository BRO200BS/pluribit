/*eslint-disable block-scoped-var, id-length, no-control-regex, no-magic-numbers, no-prototype-builtins, no-redeclare, no-shadow, no-var, sort-vars*/
"use strict";

var $protobuf = require("protobufjs/minimal");

// Common aliases
var $Reader = $protobuf.Reader, $Writer = $protobuf.Writer, $util = $protobuf.util;

// Exported root namespace
var $root = $protobuf.roots["default"] || ($protobuf.roots["default"] = {});

$root.p2p = (function() {

    /**
     * Namespace p2p.
     * @exports p2p
     * @namespace
     */
    var p2p = {};

    p2p.VrfProof = (function() {

        /**
         * Properties of a VrfProof.
         * @memberof p2p
         * @interface IVrfProof
         * @property {Uint8Array|null} [gamma] VrfProof gamma
         * @property {Uint8Array|null} [c] VrfProof c
         * @property {Uint8Array|null} [s] VrfProof s
         * @property {Uint8Array|null} [output] VrfProof output
         */

        /**
         * Constructs a new VrfProof.
         * @memberof p2p
         * @classdesc Represents a VrfProof.
         * @implements IVrfProof
         * @constructor
         * @param {p2p.IVrfProof=} [properties] Properties to set
         */
        function VrfProof(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * VrfProof gamma.
         * @member {Uint8Array} gamma
         * @memberof p2p.VrfProof
         * @instance
         */
        VrfProof.prototype.gamma = $util.newBuffer([]);

        /**
         * VrfProof c.
         * @member {Uint8Array} c
         * @memberof p2p.VrfProof
         * @instance
         */
        VrfProof.prototype.c = $util.newBuffer([]);

        /**
         * VrfProof s.
         * @member {Uint8Array} s
         * @memberof p2p.VrfProof
         * @instance
         */
        VrfProof.prototype.s = $util.newBuffer([]);

        /**
         * VrfProof output.
         * @member {Uint8Array} output
         * @memberof p2p.VrfProof
         * @instance
         */
        VrfProof.prototype.output = $util.newBuffer([]);

        /**
         * Creates a new VrfProof instance using the specified properties.
         * @function create
         * @memberof p2p.VrfProof
         * @static
         * @param {p2p.IVrfProof=} [properties] Properties to set
         * @returns {p2p.VrfProof} VrfProof instance
         */
        VrfProof.create = function create(properties) {
            return new VrfProof(properties);
        };

        /**
         * Encodes the specified VrfProof message. Does not implicitly {@link p2p.VrfProof.verify|verify} messages.
         * @function encode
         * @memberof p2p.VrfProof
         * @static
         * @param {p2p.IVrfProof} message VrfProof message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        VrfProof.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.gamma != null && Object.hasOwnProperty.call(message, "gamma"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.gamma);
            if (message.c != null && Object.hasOwnProperty.call(message, "c"))
                writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.c);
            if (message.s != null && Object.hasOwnProperty.call(message, "s"))
                writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.s);
            if (message.output != null && Object.hasOwnProperty.call(message, "output"))
                writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.output);
            return writer;
        };

        /**
         * Encodes the specified VrfProof message, length delimited. Does not implicitly {@link p2p.VrfProof.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.VrfProof
         * @static
         * @param {p2p.IVrfProof} message VrfProof message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        VrfProof.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a VrfProof message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.VrfProof
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.VrfProof} VrfProof
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        VrfProof.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.VrfProof();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.gamma = reader.bytes();
                        break;
                    }
                case 2: {
                        message.c = reader.bytes();
                        break;
                    }
                case 3: {
                        message.s = reader.bytes();
                        break;
                    }
                case 4: {
                        message.output = reader.bytes();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a VrfProof message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.VrfProof
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.VrfProof} VrfProof
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        VrfProof.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a VrfProof message.
         * @function verify
         * @memberof p2p.VrfProof
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        VrfProof.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.gamma != null && message.hasOwnProperty("gamma"))
                if (!(message.gamma && typeof message.gamma.length === "number" || $util.isString(message.gamma)))
                    return "gamma: buffer expected";
            if (message.c != null && message.hasOwnProperty("c"))
                if (!(message.c && typeof message.c.length === "number" || $util.isString(message.c)))
                    return "c: buffer expected";
            if (message.s != null && message.hasOwnProperty("s"))
                if (!(message.s && typeof message.s.length === "number" || $util.isString(message.s)))
                    return "s: buffer expected";
            if (message.output != null && message.hasOwnProperty("output"))
                if (!(message.output && typeof message.output.length === "number" || $util.isString(message.output)))
                    return "output: buffer expected";
            return null;
        };

        /**
         * Creates a VrfProof message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.VrfProof
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.VrfProof} VrfProof
         */
        VrfProof.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.VrfProof)
                return object;
            var message = new $root.p2p.VrfProof();
            if (object.gamma != null)
                if (typeof object.gamma === "string")
                    $util.base64.decode(object.gamma, message.gamma = $util.newBuffer($util.base64.length(object.gamma)), 0);
                else if (object.gamma.length >= 0)
                    message.gamma = object.gamma;
            if (object.c != null)
                if (typeof object.c === "string")
                    $util.base64.decode(object.c, message.c = $util.newBuffer($util.base64.length(object.c)), 0);
                else if (object.c.length >= 0)
                    message.c = object.c;
            if (object.s != null)
                if (typeof object.s === "string")
                    $util.base64.decode(object.s, message.s = $util.newBuffer($util.base64.length(object.s)), 0);
                else if (object.s.length >= 0)
                    message.s = object.s;
            if (object.output != null)
                if (typeof object.output === "string")
                    $util.base64.decode(object.output, message.output = $util.newBuffer($util.base64.length(object.output)), 0);
                else if (object.output.length >= 0)
                    message.output = object.output;
            return message;
        };

        /**
         * Creates a plain object from a VrfProof message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.VrfProof
         * @static
         * @param {p2p.VrfProof} message VrfProof
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        VrfProof.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.gamma = "";
                else {
                    object.gamma = [];
                    if (options.bytes !== Array)
                        object.gamma = $util.newBuffer(object.gamma);
                }
                if (options.bytes === String)
                    object.c = "";
                else {
                    object.c = [];
                    if (options.bytes !== Array)
                        object.c = $util.newBuffer(object.c);
                }
                if (options.bytes === String)
                    object.s = "";
                else {
                    object.s = [];
                    if (options.bytes !== Array)
                        object.s = $util.newBuffer(object.s);
                }
                if (options.bytes === String)
                    object.output = "";
                else {
                    object.output = [];
                    if (options.bytes !== Array)
                        object.output = $util.newBuffer(object.output);
                }
            }
            if (message.gamma != null && message.hasOwnProperty("gamma"))
                object.gamma = options.bytes === String ? $util.base64.encode(message.gamma, 0, message.gamma.length) : options.bytes === Array ? Array.prototype.slice.call(message.gamma) : message.gamma;
            if (message.c != null && message.hasOwnProperty("c"))
                object.c = options.bytes === String ? $util.base64.encode(message.c, 0, message.c.length) : options.bytes === Array ? Array.prototype.slice.call(message.c) : message.c;
            if (message.s != null && message.hasOwnProperty("s"))
                object.s = options.bytes === String ? $util.base64.encode(message.s, 0, message.s.length) : options.bytes === Array ? Array.prototype.slice.call(message.s) : message.s;
            if (message.output != null && message.hasOwnProperty("output"))
                object.output = options.bytes === String ? $util.base64.encode(message.output, 0, message.output.length) : options.bytes === Array ? Array.prototype.slice.call(message.output) : message.output;
            return object;
        };

        /**
         * Converts this VrfProof to JSON.
         * @function toJSON
         * @memberof p2p.VrfProof
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        VrfProof.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for VrfProof
         * @function getTypeUrl
         * @memberof p2p.VrfProof
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        VrfProof.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.VrfProof";
        };

        return VrfProof;
    })();

    p2p.VdfProof = (function() {

        /**
         * Properties of a VdfProof.
         * @memberof p2p
         * @interface IVdfProof
         * @property {Uint8Array|null} [y] VdfProof y
         * @property {Uint8Array|null} [pi] VdfProof pi
         * @property {Uint8Array|null} [l] VdfProof l
         * @property {Uint8Array|null} [r] VdfProof r
         * @property {number|Long|null} [iterations] VdfProof iterations
         */

        /**
         * Constructs a new VdfProof.
         * @memberof p2p
         * @classdesc Represents a VdfProof.
         * @implements IVdfProof
         * @constructor
         * @param {p2p.IVdfProof=} [properties] Properties to set
         */
        function VdfProof(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * VdfProof y.
         * @member {Uint8Array} y
         * @memberof p2p.VdfProof
         * @instance
         */
        VdfProof.prototype.y = $util.newBuffer([]);

        /**
         * VdfProof pi.
         * @member {Uint8Array} pi
         * @memberof p2p.VdfProof
         * @instance
         */
        VdfProof.prototype.pi = $util.newBuffer([]);

        /**
         * VdfProof l.
         * @member {Uint8Array} l
         * @memberof p2p.VdfProof
         * @instance
         */
        VdfProof.prototype.l = $util.newBuffer([]);

        /**
         * VdfProof r.
         * @member {Uint8Array} r
         * @memberof p2p.VdfProof
         * @instance
         */
        VdfProof.prototype.r = $util.newBuffer([]);

        /**
         * VdfProof iterations.
         * @member {number|Long} iterations
         * @memberof p2p.VdfProof
         * @instance
         */
        VdfProof.prototype.iterations = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Creates a new VdfProof instance using the specified properties.
         * @function create
         * @memberof p2p.VdfProof
         * @static
         * @param {p2p.IVdfProof=} [properties] Properties to set
         * @returns {p2p.VdfProof} VdfProof instance
         */
        VdfProof.create = function create(properties) {
            return new VdfProof(properties);
        };

        /**
         * Encodes the specified VdfProof message. Does not implicitly {@link p2p.VdfProof.verify|verify} messages.
         * @function encode
         * @memberof p2p.VdfProof
         * @static
         * @param {p2p.IVdfProof} message VdfProof message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        VdfProof.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.y != null && Object.hasOwnProperty.call(message, "y"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.y);
            if (message.pi != null && Object.hasOwnProperty.call(message, "pi"))
                writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.pi);
            if (message.l != null && Object.hasOwnProperty.call(message, "l"))
                writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.l);
            if (message.r != null && Object.hasOwnProperty.call(message, "r"))
                writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.r);
            if (message.iterations != null && Object.hasOwnProperty.call(message, "iterations"))
                writer.uint32(/* id 5, wireType 0 =*/40).uint64(message.iterations);
            return writer;
        };

        /**
         * Encodes the specified VdfProof message, length delimited. Does not implicitly {@link p2p.VdfProof.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.VdfProof
         * @static
         * @param {p2p.IVdfProof} message VdfProof message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        VdfProof.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a VdfProof message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.VdfProof
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.VdfProof} VdfProof
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        VdfProof.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.VdfProof();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.y = reader.bytes();
                        break;
                    }
                case 2: {
                        message.pi = reader.bytes();
                        break;
                    }
                case 3: {
                        message.l = reader.bytes();
                        break;
                    }
                case 4: {
                        message.r = reader.bytes();
                        break;
                    }
                case 5: {
                        message.iterations = reader.uint64();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a VdfProof message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.VdfProof
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.VdfProof} VdfProof
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        VdfProof.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a VdfProof message.
         * @function verify
         * @memberof p2p.VdfProof
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        VdfProof.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.y != null && message.hasOwnProperty("y"))
                if (!(message.y && typeof message.y.length === "number" || $util.isString(message.y)))
                    return "y: buffer expected";
            if (message.pi != null && message.hasOwnProperty("pi"))
                if (!(message.pi && typeof message.pi.length === "number" || $util.isString(message.pi)))
                    return "pi: buffer expected";
            if (message.l != null && message.hasOwnProperty("l"))
                if (!(message.l && typeof message.l.length === "number" || $util.isString(message.l)))
                    return "l: buffer expected";
            if (message.r != null && message.hasOwnProperty("r"))
                if (!(message.r && typeof message.r.length === "number" || $util.isString(message.r)))
                    return "r: buffer expected";
            if (message.iterations != null && message.hasOwnProperty("iterations"))
                if (!$util.isInteger(message.iterations) && !(message.iterations && $util.isInteger(message.iterations.low) && $util.isInteger(message.iterations.high)))
                    return "iterations: integer|Long expected";
            return null;
        };

        /**
         * Creates a VdfProof message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.VdfProof
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.VdfProof} VdfProof
         */
        VdfProof.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.VdfProof)
                return object;
            var message = new $root.p2p.VdfProof();
            if (object.y != null)
                if (typeof object.y === "string")
                    $util.base64.decode(object.y, message.y = $util.newBuffer($util.base64.length(object.y)), 0);
                else if (object.y.length >= 0)
                    message.y = object.y;
            if (object.pi != null)
                if (typeof object.pi === "string")
                    $util.base64.decode(object.pi, message.pi = $util.newBuffer($util.base64.length(object.pi)), 0);
                else if (object.pi.length >= 0)
                    message.pi = object.pi;
            if (object.l != null)
                if (typeof object.l === "string")
                    $util.base64.decode(object.l, message.l = $util.newBuffer($util.base64.length(object.l)), 0);
                else if (object.l.length >= 0)
                    message.l = object.l;
            if (object.r != null)
                if (typeof object.r === "string")
                    $util.base64.decode(object.r, message.r = $util.newBuffer($util.base64.length(object.r)), 0);
                else if (object.r.length >= 0)
                    message.r = object.r;
            if (object.iterations != null)
                if ($util.Long)
                    (message.iterations = $util.Long.fromValue(object.iterations)).unsigned = true;
                else if (typeof object.iterations === "string")
                    message.iterations = parseInt(object.iterations, 10);
                else if (typeof object.iterations === "number")
                    message.iterations = object.iterations;
                else if (typeof object.iterations === "object")
                    message.iterations = new $util.LongBits(object.iterations.low >>> 0, object.iterations.high >>> 0).toNumber(true);
            return message;
        };

        /**
         * Creates a plain object from a VdfProof message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.VdfProof
         * @static
         * @param {p2p.VdfProof} message VdfProof
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        VdfProof.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.y = "";
                else {
                    object.y = [];
                    if (options.bytes !== Array)
                        object.y = $util.newBuffer(object.y);
                }
                if (options.bytes === String)
                    object.pi = "";
                else {
                    object.pi = [];
                    if (options.bytes !== Array)
                        object.pi = $util.newBuffer(object.pi);
                }
                if (options.bytes === String)
                    object.l = "";
                else {
                    object.l = [];
                    if (options.bytes !== Array)
                        object.l = $util.newBuffer(object.l);
                }
                if (options.bytes === String)
                    object.r = "";
                else {
                    object.r = [];
                    if (options.bytes !== Array)
                        object.r = $util.newBuffer(object.r);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.iterations = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.iterations = options.longs === String ? "0" : 0;
            }
            if (message.y != null && message.hasOwnProperty("y"))
                object.y = options.bytes === String ? $util.base64.encode(message.y, 0, message.y.length) : options.bytes === Array ? Array.prototype.slice.call(message.y) : message.y;
            if (message.pi != null && message.hasOwnProperty("pi"))
                object.pi = options.bytes === String ? $util.base64.encode(message.pi, 0, message.pi.length) : options.bytes === Array ? Array.prototype.slice.call(message.pi) : message.pi;
            if (message.l != null && message.hasOwnProperty("l"))
                object.l = options.bytes === String ? $util.base64.encode(message.l, 0, message.l.length) : options.bytes === Array ? Array.prototype.slice.call(message.l) : message.l;
            if (message.r != null && message.hasOwnProperty("r"))
                object.r = options.bytes === String ? $util.base64.encode(message.r, 0, message.r.length) : options.bytes === Array ? Array.prototype.slice.call(message.r) : message.r;
            if (message.iterations != null && message.hasOwnProperty("iterations"))
                if (typeof message.iterations === "number")
                    object.iterations = options.longs === String ? String(message.iterations) : message.iterations;
                else
                    object.iterations = options.longs === String ? $util.Long.prototype.toString.call(message.iterations) : options.longs === Number ? new $util.LongBits(message.iterations.low >>> 0, message.iterations.high >>> 0).toNumber(true) : message.iterations;
            return object;
        };

        /**
         * Converts this VdfProof to JSON.
         * @function toJSON
         * @memberof p2p.VdfProof
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        VdfProof.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for VdfProof
         * @function getTypeUrl
         * @memberof p2p.VdfProof
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        VdfProof.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.VdfProof";
        };

        return VdfProof;
    })();

    p2p.Challenge = (function() {

        /**
         * Properties of a Challenge.
         * @memberof p2p
         * @interface IChallenge
         * @property {string|null} [challenge] Challenge challenge
         * @property {string|null} [from] Challenge from
         */

        /**
         * Constructs a new Challenge.
         * @memberof p2p
         * @classdesc Represents a Challenge.
         * @implements IChallenge
         * @constructor
         * @param {p2p.IChallenge=} [properties] Properties to set
         */
        function Challenge(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * Challenge challenge.
         * @member {string} challenge
         * @memberof p2p.Challenge
         * @instance
         */
        Challenge.prototype.challenge = "";

        /**
         * Challenge from.
         * @member {string} from
         * @memberof p2p.Challenge
         * @instance
         */
        Challenge.prototype.from = "";

        /**
         * Creates a new Challenge instance using the specified properties.
         * @function create
         * @memberof p2p.Challenge
         * @static
         * @param {p2p.IChallenge=} [properties] Properties to set
         * @returns {p2p.Challenge} Challenge instance
         */
        Challenge.create = function create(properties) {
            return new Challenge(properties);
        };

        /**
         * Encodes the specified Challenge message. Does not implicitly {@link p2p.Challenge.verify|verify} messages.
         * @function encode
         * @memberof p2p.Challenge
         * @static
         * @param {p2p.IChallenge} message Challenge message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        Challenge.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.challenge != null && Object.hasOwnProperty.call(message, "challenge"))
                writer.uint32(/* id 1, wireType 2 =*/10).string(message.challenge);
            if (message.from != null && Object.hasOwnProperty.call(message, "from"))
                writer.uint32(/* id 2, wireType 2 =*/18).string(message.from);
            return writer;
        };

        /**
         * Encodes the specified Challenge message, length delimited. Does not implicitly {@link p2p.Challenge.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.Challenge
         * @static
         * @param {p2p.IChallenge} message Challenge message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        Challenge.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a Challenge message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.Challenge
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.Challenge} Challenge
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        Challenge.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.Challenge();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.challenge = reader.string();
                        break;
                    }
                case 2: {
                        message.from = reader.string();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a Challenge message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.Challenge
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.Challenge} Challenge
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        Challenge.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a Challenge message.
         * @function verify
         * @memberof p2p.Challenge
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        Challenge.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.challenge != null && message.hasOwnProperty("challenge"))
                if (!$util.isString(message.challenge))
                    return "challenge: string expected";
            if (message.from != null && message.hasOwnProperty("from"))
                if (!$util.isString(message.from))
                    return "from: string expected";
            return null;
        };

        /**
         * Creates a Challenge message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.Challenge
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.Challenge} Challenge
         */
        Challenge.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.Challenge)
                return object;
            var message = new $root.p2p.Challenge();
            if (object.challenge != null)
                message.challenge = String(object.challenge);
            if (object.from != null)
                message.from = String(object.from);
            return message;
        };

        /**
         * Creates a plain object from a Challenge message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.Challenge
         * @static
         * @param {p2p.Challenge} message Challenge
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        Challenge.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                object.challenge = "";
                object.from = "";
            }
            if (message.challenge != null && message.hasOwnProperty("challenge"))
                object.challenge = message.challenge;
            if (message.from != null && message.hasOwnProperty("from"))
                object.from = message.from;
            return object;
        };

        /**
         * Converts this Challenge to JSON.
         * @function toJSON
         * @memberof p2p.Challenge
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        Challenge.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for Challenge
         * @function getTypeUrl
         * @memberof p2p.Challenge
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        Challenge.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.Challenge";
        };

        return Challenge;
    })();

    p2p.ChallengeResponse = (function() {

        /**
         * Properties of a ChallengeResponse.
         * @memberof p2p
         * @interface IChallengeResponse
         * @property {string|null} [solution] ChallengeResponse solution
         * @property {string|null} [nonce] ChallengeResponse nonce
         * @property {string|null} [from] ChallengeResponse from
         */

        /**
         * Constructs a new ChallengeResponse.
         * @memberof p2p
         * @classdesc Represents a ChallengeResponse.
         * @implements IChallengeResponse
         * @constructor
         * @param {p2p.IChallengeResponse=} [properties] Properties to set
         */
        function ChallengeResponse(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * ChallengeResponse solution.
         * @member {string} solution
         * @memberof p2p.ChallengeResponse
         * @instance
         */
        ChallengeResponse.prototype.solution = "";

        /**
         * ChallengeResponse nonce.
         * @member {string} nonce
         * @memberof p2p.ChallengeResponse
         * @instance
         */
        ChallengeResponse.prototype.nonce = "";

        /**
         * ChallengeResponse from.
         * @member {string} from
         * @memberof p2p.ChallengeResponse
         * @instance
         */
        ChallengeResponse.prototype.from = "";

        /**
         * Creates a new ChallengeResponse instance using the specified properties.
         * @function create
         * @memberof p2p.ChallengeResponse
         * @static
         * @param {p2p.IChallengeResponse=} [properties] Properties to set
         * @returns {p2p.ChallengeResponse} ChallengeResponse instance
         */
        ChallengeResponse.create = function create(properties) {
            return new ChallengeResponse(properties);
        };

        /**
         * Encodes the specified ChallengeResponse message. Does not implicitly {@link p2p.ChallengeResponse.verify|verify} messages.
         * @function encode
         * @memberof p2p.ChallengeResponse
         * @static
         * @param {p2p.IChallengeResponse} message ChallengeResponse message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        ChallengeResponse.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.solution != null && Object.hasOwnProperty.call(message, "solution"))
                writer.uint32(/* id 1, wireType 2 =*/10).string(message.solution);
            if (message.nonce != null && Object.hasOwnProperty.call(message, "nonce"))
                writer.uint32(/* id 2, wireType 2 =*/18).string(message.nonce);
            if (message.from != null && Object.hasOwnProperty.call(message, "from"))
                writer.uint32(/* id 3, wireType 2 =*/26).string(message.from);
            return writer;
        };

        /**
         * Encodes the specified ChallengeResponse message, length delimited. Does not implicitly {@link p2p.ChallengeResponse.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.ChallengeResponse
         * @static
         * @param {p2p.IChallengeResponse} message ChallengeResponse message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        ChallengeResponse.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a ChallengeResponse message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.ChallengeResponse
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.ChallengeResponse} ChallengeResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        ChallengeResponse.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.ChallengeResponse();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.solution = reader.string();
                        break;
                    }
                case 2: {
                        message.nonce = reader.string();
                        break;
                    }
                case 3: {
                        message.from = reader.string();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a ChallengeResponse message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.ChallengeResponse
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.ChallengeResponse} ChallengeResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        ChallengeResponse.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a ChallengeResponse message.
         * @function verify
         * @memberof p2p.ChallengeResponse
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        ChallengeResponse.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.solution != null && message.hasOwnProperty("solution"))
                if (!$util.isString(message.solution))
                    return "solution: string expected";
            if (message.nonce != null && message.hasOwnProperty("nonce"))
                if (!$util.isString(message.nonce))
                    return "nonce: string expected";
            if (message.from != null && message.hasOwnProperty("from"))
                if (!$util.isString(message.from))
                    return "from: string expected";
            return null;
        };

        /**
         * Creates a ChallengeResponse message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.ChallengeResponse
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.ChallengeResponse} ChallengeResponse
         */
        ChallengeResponse.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.ChallengeResponse)
                return object;
            var message = new $root.p2p.ChallengeResponse();
            if (object.solution != null)
                message.solution = String(object.solution);
            if (object.nonce != null)
                message.nonce = String(object.nonce);
            if (object.from != null)
                message.from = String(object.from);
            return message;
        };

        /**
         * Creates a plain object from a ChallengeResponse message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.ChallengeResponse
         * @static
         * @param {p2p.ChallengeResponse} message ChallengeResponse
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        ChallengeResponse.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                object.solution = "";
                object.nonce = "";
                object.from = "";
            }
            if (message.solution != null && message.hasOwnProperty("solution"))
                object.solution = message.solution;
            if (message.nonce != null && message.hasOwnProperty("nonce"))
                object.nonce = message.nonce;
            if (message.from != null && message.hasOwnProperty("from"))
                object.from = message.from;
            return object;
        };

        /**
         * Converts this ChallengeResponse to JSON.
         * @function toJSON
         * @memberof p2p.ChallengeResponse
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        ChallengeResponse.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for ChallengeResponse
         * @function getTypeUrl
         * @memberof p2p.ChallengeResponse
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        ChallengeResponse.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.ChallengeResponse";
        };

        return ChallengeResponse;
    })();

    p2p.DirectBlockRequest = (function() {

        /**
         * Properties of a DirectBlockRequest.
         * @memberof p2p
         * @interface IDirectBlockRequest
         * @property {string|null} [hash] DirectBlockRequest hash
         */

        /**
         * Constructs a new DirectBlockRequest.
         * @memberof p2p
         * @classdesc Represents a DirectBlockRequest.
         * @implements IDirectBlockRequest
         * @constructor
         * @param {p2p.IDirectBlockRequest=} [properties] Properties to set
         */
        function DirectBlockRequest(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * DirectBlockRequest hash.
         * @member {string} hash
         * @memberof p2p.DirectBlockRequest
         * @instance
         */
        DirectBlockRequest.prototype.hash = "";

        /**
         * Creates a new DirectBlockRequest instance using the specified properties.
         * @function create
         * @memberof p2p.DirectBlockRequest
         * @static
         * @param {p2p.IDirectBlockRequest=} [properties] Properties to set
         * @returns {p2p.DirectBlockRequest} DirectBlockRequest instance
         */
        DirectBlockRequest.create = function create(properties) {
            return new DirectBlockRequest(properties);
        };

        /**
         * Encodes the specified DirectBlockRequest message. Does not implicitly {@link p2p.DirectBlockRequest.verify|verify} messages.
         * @function encode
         * @memberof p2p.DirectBlockRequest
         * @static
         * @param {p2p.IDirectBlockRequest} message DirectBlockRequest message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        DirectBlockRequest.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.hash != null && Object.hasOwnProperty.call(message, "hash"))
                writer.uint32(/* id 1, wireType 2 =*/10).string(message.hash);
            return writer;
        };

        /**
         * Encodes the specified DirectBlockRequest message, length delimited. Does not implicitly {@link p2p.DirectBlockRequest.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.DirectBlockRequest
         * @static
         * @param {p2p.IDirectBlockRequest} message DirectBlockRequest message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        DirectBlockRequest.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a DirectBlockRequest message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.DirectBlockRequest
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.DirectBlockRequest} DirectBlockRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        DirectBlockRequest.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.DirectBlockRequest();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.hash = reader.string();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a DirectBlockRequest message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.DirectBlockRequest
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.DirectBlockRequest} DirectBlockRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        DirectBlockRequest.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a DirectBlockRequest message.
         * @function verify
         * @memberof p2p.DirectBlockRequest
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        DirectBlockRequest.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.hash != null && message.hasOwnProperty("hash"))
                if (!$util.isString(message.hash))
                    return "hash: string expected";
            return null;
        };

        /**
         * Creates a DirectBlockRequest message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.DirectBlockRequest
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.DirectBlockRequest} DirectBlockRequest
         */
        DirectBlockRequest.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.DirectBlockRequest)
                return object;
            var message = new $root.p2p.DirectBlockRequest();
            if (object.hash != null)
                message.hash = String(object.hash);
            return message;
        };

        /**
         * Creates a plain object from a DirectBlockRequest message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.DirectBlockRequest
         * @static
         * @param {p2p.DirectBlockRequest} message DirectBlockRequest
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        DirectBlockRequest.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults)
                object.hash = "";
            if (message.hash != null && message.hasOwnProperty("hash"))
                object.hash = message.hash;
            return object;
        };

        /**
         * Converts this DirectBlockRequest to JSON.
         * @function toJSON
         * @memberof p2p.DirectBlockRequest
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        DirectBlockRequest.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for DirectBlockRequest
         * @function getTypeUrl
         * @memberof p2p.DirectBlockRequest
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        DirectBlockRequest.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.DirectBlockRequest";
        };

        return DirectBlockRequest;
    })();

    p2p.BlockTransferResponse = (function() {

        /**
         * Properties of a BlockTransferResponse.
         * @memberof p2p
         * @interface IBlockTransferResponse
         * @property {p2p.IBlock|null} [blockData] BlockTransferResponse blockData
         * @property {string|null} [errorReason] BlockTransferResponse errorReason
         */

        /**
         * Constructs a new BlockTransferResponse.
         * @memberof p2p
         * @classdesc Represents a BlockTransferResponse.
         * @implements IBlockTransferResponse
         * @constructor
         * @param {p2p.IBlockTransferResponse=} [properties] Properties to set
         */
        function BlockTransferResponse(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * BlockTransferResponse blockData.
         * @member {p2p.IBlock|null|undefined} blockData
         * @memberof p2p.BlockTransferResponse
         * @instance
         */
        BlockTransferResponse.prototype.blockData = null;

        /**
         * BlockTransferResponse errorReason.
         * @member {string|null|undefined} errorReason
         * @memberof p2p.BlockTransferResponse
         * @instance
         */
        BlockTransferResponse.prototype.errorReason = null;

        // OneOf field names bound to virtual getters and setters
        var $oneOfFields;

        /**
         * BlockTransferResponse payload.
         * @member {"blockData"|"errorReason"|undefined} payload
         * @memberof p2p.BlockTransferResponse
         * @instance
         */
        Object.defineProperty(BlockTransferResponse.prototype, "payload", {
            get: $util.oneOfGetter($oneOfFields = ["blockData", "errorReason"]),
            set: $util.oneOfSetter($oneOfFields)
        });

        /**
         * Creates a new BlockTransferResponse instance using the specified properties.
         * @function create
         * @memberof p2p.BlockTransferResponse
         * @static
         * @param {p2p.IBlockTransferResponse=} [properties] Properties to set
         * @returns {p2p.BlockTransferResponse} BlockTransferResponse instance
         */
        BlockTransferResponse.create = function create(properties) {
            return new BlockTransferResponse(properties);
        };

        /**
         * Encodes the specified BlockTransferResponse message. Does not implicitly {@link p2p.BlockTransferResponse.verify|verify} messages.
         * @function encode
         * @memberof p2p.BlockTransferResponse
         * @static
         * @param {p2p.IBlockTransferResponse} message BlockTransferResponse message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        BlockTransferResponse.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.blockData != null && Object.hasOwnProperty.call(message, "blockData"))
                $root.p2p.Block.encode(message.blockData, writer.uint32(/* id 1, wireType 2 =*/10).fork()).ldelim();
            if (message.errorReason != null && Object.hasOwnProperty.call(message, "errorReason"))
                writer.uint32(/* id 2, wireType 2 =*/18).string(message.errorReason);
            return writer;
        };

        /**
         * Encodes the specified BlockTransferResponse message, length delimited. Does not implicitly {@link p2p.BlockTransferResponse.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.BlockTransferResponse
         * @static
         * @param {p2p.IBlockTransferResponse} message BlockTransferResponse message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        BlockTransferResponse.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a BlockTransferResponse message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.BlockTransferResponse
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.BlockTransferResponse} BlockTransferResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        BlockTransferResponse.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.BlockTransferResponse();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.blockData = $root.p2p.Block.decode(reader, reader.uint32());
                        break;
                    }
                case 2: {
                        message.errorReason = reader.string();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a BlockTransferResponse message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.BlockTransferResponse
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.BlockTransferResponse} BlockTransferResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        BlockTransferResponse.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a BlockTransferResponse message.
         * @function verify
         * @memberof p2p.BlockTransferResponse
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        BlockTransferResponse.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            var properties = {};
            if (message.blockData != null && message.hasOwnProperty("blockData")) {
                properties.payload = 1;
                {
                    var error = $root.p2p.Block.verify(message.blockData);
                    if (error)
                        return "blockData." + error;
                }
            }
            if (message.errorReason != null && message.hasOwnProperty("errorReason")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                if (!$util.isString(message.errorReason))
                    return "errorReason: string expected";
            }
            return null;
        };

        /**
         * Creates a BlockTransferResponse message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.BlockTransferResponse
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.BlockTransferResponse} BlockTransferResponse
         */
        BlockTransferResponse.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.BlockTransferResponse)
                return object;
            var message = new $root.p2p.BlockTransferResponse();
            if (object.blockData != null) {
                if (typeof object.blockData !== "object")
                    throw TypeError(".p2p.BlockTransferResponse.blockData: object expected");
                message.blockData = $root.p2p.Block.fromObject(object.blockData);
            }
            if (object.errorReason != null)
                message.errorReason = String(object.errorReason);
            return message;
        };

        /**
         * Creates a plain object from a BlockTransferResponse message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.BlockTransferResponse
         * @static
         * @param {p2p.BlockTransferResponse} message BlockTransferResponse
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        BlockTransferResponse.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (message.blockData != null && message.hasOwnProperty("blockData")) {
                object.blockData = $root.p2p.Block.toObject(message.blockData, options);
                if (options.oneofs)
                    object.payload = "blockData";
            }
            if (message.errorReason != null && message.hasOwnProperty("errorReason")) {
                object.errorReason = message.errorReason;
                if (options.oneofs)
                    object.payload = "errorReason";
            }
            return object;
        };

        /**
         * Converts this BlockTransferResponse to JSON.
         * @function toJSON
         * @memberof p2p.BlockTransferResponse
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        BlockTransferResponse.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for BlockTransferResponse
         * @function getTypeUrl
         * @memberof p2p.BlockTransferResponse
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        BlockTransferResponse.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.BlockTransferResponse";
        };

        return BlockTransferResponse;
    })();

    p2p.TransactionInput = (function() {

        /**
         * Properties of a TransactionInput.
         * @memberof p2p
         * @interface ITransactionInput
         * @property {Uint8Array|null} [commitment] TransactionInput commitment
         * @property {number|Long|null} [sourceHeight] TransactionInput sourceHeight
         */

        /**
         * Constructs a new TransactionInput.
         * @memberof p2p
         * @classdesc Represents a TransactionInput.
         * @implements ITransactionInput
         * @constructor
         * @param {p2p.ITransactionInput=} [properties] Properties to set
         */
        function TransactionInput(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * TransactionInput commitment.
         * @member {Uint8Array} commitment
         * @memberof p2p.TransactionInput
         * @instance
         */
        TransactionInput.prototype.commitment = $util.newBuffer([]);

        /**
         * TransactionInput sourceHeight.
         * @member {number|Long} sourceHeight
         * @memberof p2p.TransactionInput
         * @instance
         */
        TransactionInput.prototype.sourceHeight = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Creates a new TransactionInput instance using the specified properties.
         * @function create
         * @memberof p2p.TransactionInput
         * @static
         * @param {p2p.ITransactionInput=} [properties] Properties to set
         * @returns {p2p.TransactionInput} TransactionInput instance
         */
        TransactionInput.create = function create(properties) {
            return new TransactionInput(properties);
        };

        /**
         * Encodes the specified TransactionInput message. Does not implicitly {@link p2p.TransactionInput.verify|verify} messages.
         * @function encode
         * @memberof p2p.TransactionInput
         * @static
         * @param {p2p.ITransactionInput} message TransactionInput message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        TransactionInput.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.commitment != null && Object.hasOwnProperty.call(message, "commitment"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.commitment);
            if (message.sourceHeight != null && Object.hasOwnProperty.call(message, "sourceHeight"))
                writer.uint32(/* id 2, wireType 0 =*/16).uint64(message.sourceHeight);
            return writer;
        };

        /**
         * Encodes the specified TransactionInput message, length delimited. Does not implicitly {@link p2p.TransactionInput.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.TransactionInput
         * @static
         * @param {p2p.ITransactionInput} message TransactionInput message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        TransactionInput.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a TransactionInput message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.TransactionInput
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.TransactionInput} TransactionInput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        TransactionInput.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.TransactionInput();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.commitment = reader.bytes();
                        break;
                    }
                case 2: {
                        message.sourceHeight = reader.uint64();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a TransactionInput message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.TransactionInput
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.TransactionInput} TransactionInput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        TransactionInput.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a TransactionInput message.
         * @function verify
         * @memberof p2p.TransactionInput
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        TransactionInput.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.commitment != null && message.hasOwnProperty("commitment"))
                if (!(message.commitment && typeof message.commitment.length === "number" || $util.isString(message.commitment)))
                    return "commitment: buffer expected";
            if (message.sourceHeight != null && message.hasOwnProperty("sourceHeight"))
                if (!$util.isInteger(message.sourceHeight) && !(message.sourceHeight && $util.isInteger(message.sourceHeight.low) && $util.isInteger(message.sourceHeight.high)))
                    return "sourceHeight: integer|Long expected";
            return null;
        };

        /**
         * Creates a TransactionInput message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.TransactionInput
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.TransactionInput} TransactionInput
         */
        TransactionInput.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.TransactionInput)
                return object;
            var message = new $root.p2p.TransactionInput();
            if (object.commitment != null)
                if (typeof object.commitment === "string")
                    $util.base64.decode(object.commitment, message.commitment = $util.newBuffer($util.base64.length(object.commitment)), 0);
                else if (object.commitment.length >= 0)
                    message.commitment = object.commitment;
            if (object.sourceHeight != null)
                if ($util.Long)
                    (message.sourceHeight = $util.Long.fromValue(object.sourceHeight)).unsigned = true;
                else if (typeof object.sourceHeight === "string")
                    message.sourceHeight = parseInt(object.sourceHeight, 10);
                else if (typeof object.sourceHeight === "number")
                    message.sourceHeight = object.sourceHeight;
                else if (typeof object.sourceHeight === "object")
                    message.sourceHeight = new $util.LongBits(object.sourceHeight.low >>> 0, object.sourceHeight.high >>> 0).toNumber(true);
            return message;
        };

        /**
         * Creates a plain object from a TransactionInput message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.TransactionInput
         * @static
         * @param {p2p.TransactionInput} message TransactionInput
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        TransactionInput.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.commitment = "";
                else {
                    object.commitment = [];
                    if (options.bytes !== Array)
                        object.commitment = $util.newBuffer(object.commitment);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.sourceHeight = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.sourceHeight = options.longs === String ? "0" : 0;
            }
            if (message.commitment != null && message.hasOwnProperty("commitment"))
                object.commitment = options.bytes === String ? $util.base64.encode(message.commitment, 0, message.commitment.length) : options.bytes === Array ? Array.prototype.slice.call(message.commitment) : message.commitment;
            if (message.sourceHeight != null && message.hasOwnProperty("sourceHeight"))
                if (typeof message.sourceHeight === "number")
                    object.sourceHeight = options.longs === String ? String(message.sourceHeight) : message.sourceHeight;
                else
                    object.sourceHeight = options.longs === String ? $util.Long.prototype.toString.call(message.sourceHeight) : options.longs === Number ? new $util.LongBits(message.sourceHeight.low >>> 0, message.sourceHeight.high >>> 0).toNumber(true) : message.sourceHeight;
            return object;
        };

        /**
         * Converts this TransactionInput to JSON.
         * @function toJSON
         * @memberof p2p.TransactionInput
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        TransactionInput.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for TransactionInput
         * @function getTypeUrl
         * @memberof p2p.TransactionInput
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        TransactionInput.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.TransactionInput";
        };

        return TransactionInput;
    })();

    p2p.TransactionOutput = (function() {

        /**
         * Properties of a TransactionOutput.
         * @memberof p2p
         * @interface ITransactionOutput
         * @property {Uint8Array|null} [commitment] TransactionOutput commitment
         * @property {Uint8Array|null} [ephemeralKey] TransactionOutput ephemeralKey
         * @property {Uint8Array|null} [stealthPayload] TransactionOutput stealthPayload
         * @property {Uint8Array|null} [viewTag] TransactionOutput viewTag
         */

        /**
         * Constructs a new TransactionOutput.
         * @memberof p2p
         * @classdesc Represents a TransactionOutput.
         * @implements ITransactionOutput
         * @constructor
         * @param {p2p.ITransactionOutput=} [properties] Properties to set
         */
        function TransactionOutput(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * TransactionOutput commitment.
         * @member {Uint8Array} commitment
         * @memberof p2p.TransactionOutput
         * @instance
         */
        TransactionOutput.prototype.commitment = $util.newBuffer([]);

        /**
         * TransactionOutput ephemeralKey.
         * @member {Uint8Array|null|undefined} ephemeralKey
         * @memberof p2p.TransactionOutput
         * @instance
         */
        TransactionOutput.prototype.ephemeralKey = null;

        /**
         * TransactionOutput stealthPayload.
         * @member {Uint8Array|null|undefined} stealthPayload
         * @memberof p2p.TransactionOutput
         * @instance
         */
        TransactionOutput.prototype.stealthPayload = null;

        /**
         * TransactionOutput viewTag.
         * @member {Uint8Array|null|undefined} viewTag
         * @memberof p2p.TransactionOutput
         * @instance
         */
        TransactionOutput.prototype.viewTag = null;

        // OneOf field names bound to virtual getters and setters
        var $oneOfFields;

        /**
         * TransactionOutput _ephemeralKey.
         * @member {"ephemeralKey"|undefined} _ephemeralKey
         * @memberof p2p.TransactionOutput
         * @instance
         */
        Object.defineProperty(TransactionOutput.prototype, "_ephemeralKey", {
            get: $util.oneOfGetter($oneOfFields = ["ephemeralKey"]),
            set: $util.oneOfSetter($oneOfFields)
        });

        /**
         * TransactionOutput _stealthPayload.
         * @member {"stealthPayload"|undefined} _stealthPayload
         * @memberof p2p.TransactionOutput
         * @instance
         */
        Object.defineProperty(TransactionOutput.prototype, "_stealthPayload", {
            get: $util.oneOfGetter($oneOfFields = ["stealthPayload"]),
            set: $util.oneOfSetter($oneOfFields)
        });

        /**
         * TransactionOutput _viewTag.
         * @member {"viewTag"|undefined} _viewTag
         * @memberof p2p.TransactionOutput
         * @instance
         */
        Object.defineProperty(TransactionOutput.prototype, "_viewTag", {
            get: $util.oneOfGetter($oneOfFields = ["viewTag"]),
            set: $util.oneOfSetter($oneOfFields)
        });

        /**
         * Creates a new TransactionOutput instance using the specified properties.
         * @function create
         * @memberof p2p.TransactionOutput
         * @static
         * @param {p2p.ITransactionOutput=} [properties] Properties to set
         * @returns {p2p.TransactionOutput} TransactionOutput instance
         */
        TransactionOutput.create = function create(properties) {
            return new TransactionOutput(properties);
        };

        /**
         * Encodes the specified TransactionOutput message. Does not implicitly {@link p2p.TransactionOutput.verify|verify} messages.
         * @function encode
         * @memberof p2p.TransactionOutput
         * @static
         * @param {p2p.ITransactionOutput} message TransactionOutput message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        TransactionOutput.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.commitment != null && Object.hasOwnProperty.call(message, "commitment"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.commitment);
            if (message.ephemeralKey != null && Object.hasOwnProperty.call(message, "ephemeralKey"))
                writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.ephemeralKey);
            if (message.stealthPayload != null && Object.hasOwnProperty.call(message, "stealthPayload"))
                writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.stealthPayload);
            if (message.viewTag != null && Object.hasOwnProperty.call(message, "viewTag"))
                writer.uint32(/* id 5, wireType 2 =*/42).bytes(message.viewTag);
            return writer;
        };

        /**
         * Encodes the specified TransactionOutput message, length delimited. Does not implicitly {@link p2p.TransactionOutput.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.TransactionOutput
         * @static
         * @param {p2p.ITransactionOutput} message TransactionOutput message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        TransactionOutput.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a TransactionOutput message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.TransactionOutput
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.TransactionOutput} TransactionOutput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        TransactionOutput.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.TransactionOutput();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.commitment = reader.bytes();
                        break;
                    }
                case 3: {
                        message.ephemeralKey = reader.bytes();
                        break;
                    }
                case 4: {
                        message.stealthPayload = reader.bytes();
                        break;
                    }
                case 5: {
                        message.viewTag = reader.bytes();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a TransactionOutput message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.TransactionOutput
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.TransactionOutput} TransactionOutput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        TransactionOutput.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a TransactionOutput message.
         * @function verify
         * @memberof p2p.TransactionOutput
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        TransactionOutput.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            var properties = {};
            if (message.commitment != null && message.hasOwnProperty("commitment"))
                if (!(message.commitment && typeof message.commitment.length === "number" || $util.isString(message.commitment)))
                    return "commitment: buffer expected";
            if (message.ephemeralKey != null && message.hasOwnProperty("ephemeralKey")) {
                properties._ephemeralKey = 1;
                if (!(message.ephemeralKey && typeof message.ephemeralKey.length === "number" || $util.isString(message.ephemeralKey)))
                    return "ephemeralKey: buffer expected";
            }
            if (message.stealthPayload != null && message.hasOwnProperty("stealthPayload")) {
                properties._stealthPayload = 1;
                if (!(message.stealthPayload && typeof message.stealthPayload.length === "number" || $util.isString(message.stealthPayload)))
                    return "stealthPayload: buffer expected";
            }
            if (message.viewTag != null && message.hasOwnProperty("viewTag")) {
                properties._viewTag = 1;
                if (!(message.viewTag && typeof message.viewTag.length === "number" || $util.isString(message.viewTag)))
                    return "viewTag: buffer expected";
            }
            return null;
        };

        /**
         * Creates a TransactionOutput message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.TransactionOutput
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.TransactionOutput} TransactionOutput
         */
        TransactionOutput.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.TransactionOutput)
                return object;
            var message = new $root.p2p.TransactionOutput();
            if (object.commitment != null)
                if (typeof object.commitment === "string")
                    $util.base64.decode(object.commitment, message.commitment = $util.newBuffer($util.base64.length(object.commitment)), 0);
                else if (object.commitment.length >= 0)
                    message.commitment = object.commitment;
            if (object.ephemeralKey != null)
                if (typeof object.ephemeralKey === "string")
                    $util.base64.decode(object.ephemeralKey, message.ephemeralKey = $util.newBuffer($util.base64.length(object.ephemeralKey)), 0);
                else if (object.ephemeralKey.length >= 0)
                    message.ephemeralKey = object.ephemeralKey;
            if (object.stealthPayload != null)
                if (typeof object.stealthPayload === "string")
                    $util.base64.decode(object.stealthPayload, message.stealthPayload = $util.newBuffer($util.base64.length(object.stealthPayload)), 0);
                else if (object.stealthPayload.length >= 0)
                    message.stealthPayload = object.stealthPayload;
            if (object.viewTag != null)
                if (typeof object.viewTag === "string")
                    $util.base64.decode(object.viewTag, message.viewTag = $util.newBuffer($util.base64.length(object.viewTag)), 0);
                else if (object.viewTag.length >= 0)
                    message.viewTag = object.viewTag;
            return message;
        };

        /**
         * Creates a plain object from a TransactionOutput message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.TransactionOutput
         * @static
         * @param {p2p.TransactionOutput} message TransactionOutput
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        TransactionOutput.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults)
                if (options.bytes === String)
                    object.commitment = "";
                else {
                    object.commitment = [];
                    if (options.bytes !== Array)
                        object.commitment = $util.newBuffer(object.commitment);
                }
            if (message.commitment != null && message.hasOwnProperty("commitment"))
                object.commitment = options.bytes === String ? $util.base64.encode(message.commitment, 0, message.commitment.length) : options.bytes === Array ? Array.prototype.slice.call(message.commitment) : message.commitment;
            if (message.ephemeralKey != null && message.hasOwnProperty("ephemeralKey")) {
                object.ephemeralKey = options.bytes === String ? $util.base64.encode(message.ephemeralKey, 0, message.ephemeralKey.length) : options.bytes === Array ? Array.prototype.slice.call(message.ephemeralKey) : message.ephemeralKey;
                if (options.oneofs)
                    object._ephemeralKey = "ephemeralKey";
            }
            if (message.stealthPayload != null && message.hasOwnProperty("stealthPayload")) {
                object.stealthPayload = options.bytes === String ? $util.base64.encode(message.stealthPayload, 0, message.stealthPayload.length) : options.bytes === Array ? Array.prototype.slice.call(message.stealthPayload) : message.stealthPayload;
                if (options.oneofs)
                    object._stealthPayload = "stealthPayload";
            }
            if (message.viewTag != null && message.hasOwnProperty("viewTag")) {
                object.viewTag = options.bytes === String ? $util.base64.encode(message.viewTag, 0, message.viewTag.length) : options.bytes === Array ? Array.prototype.slice.call(message.viewTag) : message.viewTag;
                if (options.oneofs)
                    object._viewTag = "viewTag";
            }
            return object;
        };

        /**
         * Converts this TransactionOutput to JSON.
         * @function toJSON
         * @memberof p2p.TransactionOutput
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        TransactionOutput.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for TransactionOutput
         * @function getTypeUrl
         * @memberof p2p.TransactionOutput
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        TransactionOutput.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.TransactionOutput";
        };

        return TransactionOutput;
    })();

    p2p.TransactionKernel = (function() {

        /**
         * Properties of a TransactionKernel.
         * @memberof p2p
         * @interface ITransactionKernel
         * @property {Uint8Array|null} [excess] TransactionKernel excess
         * @property {Uint8Array|null} [signature] TransactionKernel signature
         * @property {number|Long|null} [fee] TransactionKernel fee
         * @property {number|Long|null} [minHeight] TransactionKernel minHeight
         * @property {number|Long|null} [timestamp] TransactionKernel timestamp
         */

        /**
         * Constructs a new TransactionKernel.
         * @memberof p2p
         * @classdesc Represents a TransactionKernel.
         * @implements ITransactionKernel
         * @constructor
         * @param {p2p.ITransactionKernel=} [properties] Properties to set
         */
        function TransactionKernel(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * TransactionKernel excess.
         * @member {Uint8Array} excess
         * @memberof p2p.TransactionKernel
         * @instance
         */
        TransactionKernel.prototype.excess = $util.newBuffer([]);

        /**
         * TransactionKernel signature.
         * @member {Uint8Array} signature
         * @memberof p2p.TransactionKernel
         * @instance
         */
        TransactionKernel.prototype.signature = $util.newBuffer([]);

        /**
         * TransactionKernel fee.
         * @member {number|Long} fee
         * @memberof p2p.TransactionKernel
         * @instance
         */
        TransactionKernel.prototype.fee = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * TransactionKernel minHeight.
         * @member {number|Long} minHeight
         * @memberof p2p.TransactionKernel
         * @instance
         */
        TransactionKernel.prototype.minHeight = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * TransactionKernel timestamp.
         * @member {number|Long} timestamp
         * @memberof p2p.TransactionKernel
         * @instance
         */
        TransactionKernel.prototype.timestamp = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Creates a new TransactionKernel instance using the specified properties.
         * @function create
         * @memberof p2p.TransactionKernel
         * @static
         * @param {p2p.ITransactionKernel=} [properties] Properties to set
         * @returns {p2p.TransactionKernel} TransactionKernel instance
         */
        TransactionKernel.create = function create(properties) {
            return new TransactionKernel(properties);
        };

        /**
         * Encodes the specified TransactionKernel message. Does not implicitly {@link p2p.TransactionKernel.verify|verify} messages.
         * @function encode
         * @memberof p2p.TransactionKernel
         * @static
         * @param {p2p.ITransactionKernel} message TransactionKernel message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        TransactionKernel.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.excess != null && Object.hasOwnProperty.call(message, "excess"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.excess);
            if (message.signature != null && Object.hasOwnProperty.call(message, "signature"))
                writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.signature);
            if (message.fee != null && Object.hasOwnProperty.call(message, "fee"))
                writer.uint32(/* id 3, wireType 0 =*/24).uint64(message.fee);
            if (message.minHeight != null && Object.hasOwnProperty.call(message, "minHeight"))
                writer.uint32(/* id 4, wireType 0 =*/32).uint64(message.minHeight);
            if (message.timestamp != null && Object.hasOwnProperty.call(message, "timestamp"))
                writer.uint32(/* id 5, wireType 0 =*/40).uint64(message.timestamp);
            return writer;
        };

        /**
         * Encodes the specified TransactionKernel message, length delimited. Does not implicitly {@link p2p.TransactionKernel.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.TransactionKernel
         * @static
         * @param {p2p.ITransactionKernel} message TransactionKernel message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        TransactionKernel.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a TransactionKernel message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.TransactionKernel
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.TransactionKernel} TransactionKernel
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        TransactionKernel.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.TransactionKernel();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.excess = reader.bytes();
                        break;
                    }
                case 2: {
                        message.signature = reader.bytes();
                        break;
                    }
                case 3: {
                        message.fee = reader.uint64();
                        break;
                    }
                case 4: {
                        message.minHeight = reader.uint64();
                        break;
                    }
                case 5: {
                        message.timestamp = reader.uint64();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a TransactionKernel message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.TransactionKernel
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.TransactionKernel} TransactionKernel
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        TransactionKernel.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a TransactionKernel message.
         * @function verify
         * @memberof p2p.TransactionKernel
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        TransactionKernel.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.excess != null && message.hasOwnProperty("excess"))
                if (!(message.excess && typeof message.excess.length === "number" || $util.isString(message.excess)))
                    return "excess: buffer expected";
            if (message.signature != null && message.hasOwnProperty("signature"))
                if (!(message.signature && typeof message.signature.length === "number" || $util.isString(message.signature)))
                    return "signature: buffer expected";
            if (message.fee != null && message.hasOwnProperty("fee"))
                if (!$util.isInteger(message.fee) && !(message.fee && $util.isInteger(message.fee.low) && $util.isInteger(message.fee.high)))
                    return "fee: integer|Long expected";
            if (message.minHeight != null && message.hasOwnProperty("minHeight"))
                if (!$util.isInteger(message.minHeight) && !(message.minHeight && $util.isInteger(message.minHeight.low) && $util.isInteger(message.minHeight.high)))
                    return "minHeight: integer|Long expected";
            if (message.timestamp != null && message.hasOwnProperty("timestamp"))
                if (!$util.isInteger(message.timestamp) && !(message.timestamp && $util.isInteger(message.timestamp.low) && $util.isInteger(message.timestamp.high)))
                    return "timestamp: integer|Long expected";
            return null;
        };

        /**
         * Creates a TransactionKernel message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.TransactionKernel
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.TransactionKernel} TransactionKernel
         */
        TransactionKernel.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.TransactionKernel)
                return object;
            var message = new $root.p2p.TransactionKernel();
            if (object.excess != null)
                if (typeof object.excess === "string")
                    $util.base64.decode(object.excess, message.excess = $util.newBuffer($util.base64.length(object.excess)), 0);
                else if (object.excess.length >= 0)
                    message.excess = object.excess;
            if (object.signature != null)
                if (typeof object.signature === "string")
                    $util.base64.decode(object.signature, message.signature = $util.newBuffer($util.base64.length(object.signature)), 0);
                else if (object.signature.length >= 0)
                    message.signature = object.signature;
            if (object.fee != null)
                if ($util.Long)
                    (message.fee = $util.Long.fromValue(object.fee)).unsigned = true;
                else if (typeof object.fee === "string")
                    message.fee = parseInt(object.fee, 10);
                else if (typeof object.fee === "number")
                    message.fee = object.fee;
                else if (typeof object.fee === "object")
                    message.fee = new $util.LongBits(object.fee.low >>> 0, object.fee.high >>> 0).toNumber(true);
            if (object.minHeight != null)
                if ($util.Long)
                    (message.minHeight = $util.Long.fromValue(object.minHeight)).unsigned = true;
                else if (typeof object.minHeight === "string")
                    message.minHeight = parseInt(object.minHeight, 10);
                else if (typeof object.minHeight === "number")
                    message.minHeight = object.minHeight;
                else if (typeof object.minHeight === "object")
                    message.minHeight = new $util.LongBits(object.minHeight.low >>> 0, object.minHeight.high >>> 0).toNumber(true);
            if (object.timestamp != null)
                if ($util.Long)
                    (message.timestamp = $util.Long.fromValue(object.timestamp)).unsigned = true;
                else if (typeof object.timestamp === "string")
                    message.timestamp = parseInt(object.timestamp, 10);
                else if (typeof object.timestamp === "number")
                    message.timestamp = object.timestamp;
                else if (typeof object.timestamp === "object")
                    message.timestamp = new $util.LongBits(object.timestamp.low >>> 0, object.timestamp.high >>> 0).toNumber(true);
            return message;
        };

        /**
         * Creates a plain object from a TransactionKernel message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.TransactionKernel
         * @static
         * @param {p2p.TransactionKernel} message TransactionKernel
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        TransactionKernel.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.excess = "";
                else {
                    object.excess = [];
                    if (options.bytes !== Array)
                        object.excess = $util.newBuffer(object.excess);
                }
                if (options.bytes === String)
                    object.signature = "";
                else {
                    object.signature = [];
                    if (options.bytes !== Array)
                        object.signature = $util.newBuffer(object.signature);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.fee = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.fee = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.minHeight = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.minHeight = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.timestamp = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.timestamp = options.longs === String ? "0" : 0;
            }
            if (message.excess != null && message.hasOwnProperty("excess"))
                object.excess = options.bytes === String ? $util.base64.encode(message.excess, 0, message.excess.length) : options.bytes === Array ? Array.prototype.slice.call(message.excess) : message.excess;
            if (message.signature != null && message.hasOwnProperty("signature"))
                object.signature = options.bytes === String ? $util.base64.encode(message.signature, 0, message.signature.length) : options.bytes === Array ? Array.prototype.slice.call(message.signature) : message.signature;
            if (message.fee != null && message.hasOwnProperty("fee"))
                if (typeof message.fee === "number")
                    object.fee = options.longs === String ? String(message.fee) : message.fee;
                else
                    object.fee = options.longs === String ? $util.Long.prototype.toString.call(message.fee) : options.longs === Number ? new $util.LongBits(message.fee.low >>> 0, message.fee.high >>> 0).toNumber(true) : message.fee;
            if (message.minHeight != null && message.hasOwnProperty("minHeight"))
                if (typeof message.minHeight === "number")
                    object.minHeight = options.longs === String ? String(message.minHeight) : message.minHeight;
                else
                    object.minHeight = options.longs === String ? $util.Long.prototype.toString.call(message.minHeight) : options.longs === Number ? new $util.LongBits(message.minHeight.low >>> 0, message.minHeight.high >>> 0).toNumber(true) : message.minHeight;
            if (message.timestamp != null && message.hasOwnProperty("timestamp"))
                if (typeof message.timestamp === "number")
                    object.timestamp = options.longs === String ? String(message.timestamp) : message.timestamp;
                else
                    object.timestamp = options.longs === String ? $util.Long.prototype.toString.call(message.timestamp) : options.longs === Number ? new $util.LongBits(message.timestamp.low >>> 0, message.timestamp.high >>> 0).toNumber(true) : message.timestamp;
            return object;
        };

        /**
         * Converts this TransactionKernel to JSON.
         * @function toJSON
         * @memberof p2p.TransactionKernel
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        TransactionKernel.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for TransactionKernel
         * @function getTypeUrl
         * @memberof p2p.TransactionKernel
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        TransactionKernel.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.TransactionKernel";
        };

        return TransactionKernel;
    })();

    p2p.Transaction = (function() {

        /**
         * Properties of a Transaction.
         * @memberof p2p
         * @interface ITransaction
         * @property {Array.<p2p.ITransactionInput>|null} [inputs] Transaction inputs
         * @property {Array.<p2p.ITransactionOutput>|null} [outputs] Transaction outputs
         * @property {Array.<p2p.ITransactionKernel>|null} [kernels] Transaction kernels
         * @property {number|Long|null} [timestamp] Transaction timestamp
         * @property {Uint8Array|null} [aggregatedRangeProof] Transaction aggregatedRangeProof
         */

        /**
         * Constructs a new Transaction.
         * @memberof p2p
         * @classdesc Represents a Transaction.
         * @implements ITransaction
         * @constructor
         * @param {p2p.ITransaction=} [properties] Properties to set
         */
        function Transaction(properties) {
            this.inputs = [];
            this.outputs = [];
            this.kernels = [];
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * Transaction inputs.
         * @member {Array.<p2p.ITransactionInput>} inputs
         * @memberof p2p.Transaction
         * @instance
         */
        Transaction.prototype.inputs = $util.emptyArray;

        /**
         * Transaction outputs.
         * @member {Array.<p2p.ITransactionOutput>} outputs
         * @memberof p2p.Transaction
         * @instance
         */
        Transaction.prototype.outputs = $util.emptyArray;

        /**
         * Transaction kernels.
         * @member {Array.<p2p.ITransactionKernel>} kernels
         * @memberof p2p.Transaction
         * @instance
         */
        Transaction.prototype.kernels = $util.emptyArray;

        /**
         * Transaction timestamp.
         * @member {number|Long} timestamp
         * @memberof p2p.Transaction
         * @instance
         */
        Transaction.prototype.timestamp = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Transaction aggregatedRangeProof.
         * @member {Uint8Array} aggregatedRangeProof
         * @memberof p2p.Transaction
         * @instance
         */
        Transaction.prototype.aggregatedRangeProof = $util.newBuffer([]);

        /**
         * Creates a new Transaction instance using the specified properties.
         * @function create
         * @memberof p2p.Transaction
         * @static
         * @param {p2p.ITransaction=} [properties] Properties to set
         * @returns {p2p.Transaction} Transaction instance
         */
        Transaction.create = function create(properties) {
            return new Transaction(properties);
        };

        /**
         * Encodes the specified Transaction message. Does not implicitly {@link p2p.Transaction.verify|verify} messages.
         * @function encode
         * @memberof p2p.Transaction
         * @static
         * @param {p2p.ITransaction} message Transaction message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        Transaction.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.inputs != null && message.inputs.length)
                for (var i = 0; i < message.inputs.length; ++i)
                    $root.p2p.TransactionInput.encode(message.inputs[i], writer.uint32(/* id 1, wireType 2 =*/10).fork()).ldelim();
            if (message.outputs != null && message.outputs.length)
                for (var i = 0; i < message.outputs.length; ++i)
                    $root.p2p.TransactionOutput.encode(message.outputs[i], writer.uint32(/* id 2, wireType 2 =*/18).fork()).ldelim();
            if (message.kernels != null && message.kernels.length)
                for (var i = 0; i < message.kernels.length; ++i)
                    $root.p2p.TransactionKernel.encode(message.kernels[i], writer.uint32(/* id 3, wireType 2 =*/26).fork()).ldelim();
            if (message.timestamp != null && Object.hasOwnProperty.call(message, "timestamp"))
                writer.uint32(/* id 4, wireType 0 =*/32).uint64(message.timestamp);
            if (message.aggregatedRangeProof != null && Object.hasOwnProperty.call(message, "aggregatedRangeProof"))
                writer.uint32(/* id 5, wireType 2 =*/42).bytes(message.aggregatedRangeProof);
            return writer;
        };

        /**
         * Encodes the specified Transaction message, length delimited. Does not implicitly {@link p2p.Transaction.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.Transaction
         * @static
         * @param {p2p.ITransaction} message Transaction message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        Transaction.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a Transaction message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.Transaction
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.Transaction} Transaction
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        Transaction.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.Transaction();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        if (!(message.inputs && message.inputs.length))
                            message.inputs = [];
                        message.inputs.push($root.p2p.TransactionInput.decode(reader, reader.uint32()));
                        break;
                    }
                case 2: {
                        if (!(message.outputs && message.outputs.length))
                            message.outputs = [];
                        message.outputs.push($root.p2p.TransactionOutput.decode(reader, reader.uint32()));
                        break;
                    }
                case 3: {
                        if (!(message.kernels && message.kernels.length))
                            message.kernels = [];
                        message.kernels.push($root.p2p.TransactionKernel.decode(reader, reader.uint32()));
                        break;
                    }
                case 4: {
                        message.timestamp = reader.uint64();
                        break;
                    }
                case 5: {
                        message.aggregatedRangeProof = reader.bytes();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a Transaction message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.Transaction
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.Transaction} Transaction
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        Transaction.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a Transaction message.
         * @function verify
         * @memberof p2p.Transaction
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        Transaction.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.inputs != null && message.hasOwnProperty("inputs")) {
                if (!Array.isArray(message.inputs))
                    return "inputs: array expected";
                for (var i = 0; i < message.inputs.length; ++i) {
                    var error = $root.p2p.TransactionInput.verify(message.inputs[i]);
                    if (error)
                        return "inputs." + error;
                }
            }
            if (message.outputs != null && message.hasOwnProperty("outputs")) {
                if (!Array.isArray(message.outputs))
                    return "outputs: array expected";
                for (var i = 0; i < message.outputs.length; ++i) {
                    var error = $root.p2p.TransactionOutput.verify(message.outputs[i]);
                    if (error)
                        return "outputs." + error;
                }
            }
            if (message.kernels != null && message.hasOwnProperty("kernels")) {
                if (!Array.isArray(message.kernels))
                    return "kernels: array expected";
                for (var i = 0; i < message.kernels.length; ++i) {
                    var error = $root.p2p.TransactionKernel.verify(message.kernels[i]);
                    if (error)
                        return "kernels." + error;
                }
            }
            if (message.timestamp != null && message.hasOwnProperty("timestamp"))
                if (!$util.isInteger(message.timestamp) && !(message.timestamp && $util.isInteger(message.timestamp.low) && $util.isInteger(message.timestamp.high)))
                    return "timestamp: integer|Long expected";
            if (message.aggregatedRangeProof != null && message.hasOwnProperty("aggregatedRangeProof"))
                if (!(message.aggregatedRangeProof && typeof message.aggregatedRangeProof.length === "number" || $util.isString(message.aggregatedRangeProof)))
                    return "aggregatedRangeProof: buffer expected";
            return null;
        };

        /**
         * Creates a Transaction message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.Transaction
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.Transaction} Transaction
         */
        Transaction.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.Transaction)
                return object;
            var message = new $root.p2p.Transaction();
            if (object.inputs) {
                if (!Array.isArray(object.inputs))
                    throw TypeError(".p2p.Transaction.inputs: array expected");
                message.inputs = [];
                for (var i = 0; i < object.inputs.length; ++i) {
                    if (typeof object.inputs[i] !== "object")
                        throw TypeError(".p2p.Transaction.inputs: object expected");
                    message.inputs[i] = $root.p2p.TransactionInput.fromObject(object.inputs[i]);
                }
            }
            if (object.outputs) {
                if (!Array.isArray(object.outputs))
                    throw TypeError(".p2p.Transaction.outputs: array expected");
                message.outputs = [];
                for (var i = 0; i < object.outputs.length; ++i) {
                    if (typeof object.outputs[i] !== "object")
                        throw TypeError(".p2p.Transaction.outputs: object expected");
                    message.outputs[i] = $root.p2p.TransactionOutput.fromObject(object.outputs[i]);
                }
            }
            if (object.kernels) {
                if (!Array.isArray(object.kernels))
                    throw TypeError(".p2p.Transaction.kernels: array expected");
                message.kernels = [];
                for (var i = 0; i < object.kernels.length; ++i) {
                    if (typeof object.kernels[i] !== "object")
                        throw TypeError(".p2p.Transaction.kernels: object expected");
                    message.kernels[i] = $root.p2p.TransactionKernel.fromObject(object.kernels[i]);
                }
            }
            if (object.timestamp != null)
                if ($util.Long)
                    (message.timestamp = $util.Long.fromValue(object.timestamp)).unsigned = true;
                else if (typeof object.timestamp === "string")
                    message.timestamp = parseInt(object.timestamp, 10);
                else if (typeof object.timestamp === "number")
                    message.timestamp = object.timestamp;
                else if (typeof object.timestamp === "object")
                    message.timestamp = new $util.LongBits(object.timestamp.low >>> 0, object.timestamp.high >>> 0).toNumber(true);
            if (object.aggregatedRangeProof != null)
                if (typeof object.aggregatedRangeProof === "string")
                    $util.base64.decode(object.aggregatedRangeProof, message.aggregatedRangeProof = $util.newBuffer($util.base64.length(object.aggregatedRangeProof)), 0);
                else if (object.aggregatedRangeProof.length >= 0)
                    message.aggregatedRangeProof = object.aggregatedRangeProof;
            return message;
        };

        /**
         * Creates a plain object from a Transaction message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.Transaction
         * @static
         * @param {p2p.Transaction} message Transaction
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        Transaction.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.arrays || options.defaults) {
                object.inputs = [];
                object.outputs = [];
                object.kernels = [];
            }
            if (options.defaults) {
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.timestamp = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.timestamp = options.longs === String ? "0" : 0;
                if (options.bytes === String)
                    object.aggregatedRangeProof = "";
                else {
                    object.aggregatedRangeProof = [];
                    if (options.bytes !== Array)
                        object.aggregatedRangeProof = $util.newBuffer(object.aggregatedRangeProof);
                }
            }
            if (message.inputs && message.inputs.length) {
                object.inputs = [];
                for (var j = 0; j < message.inputs.length; ++j)
                    object.inputs[j] = $root.p2p.TransactionInput.toObject(message.inputs[j], options);
            }
            if (message.outputs && message.outputs.length) {
                object.outputs = [];
                for (var j = 0; j < message.outputs.length; ++j)
                    object.outputs[j] = $root.p2p.TransactionOutput.toObject(message.outputs[j], options);
            }
            if (message.kernels && message.kernels.length) {
                object.kernels = [];
                for (var j = 0; j < message.kernels.length; ++j)
                    object.kernels[j] = $root.p2p.TransactionKernel.toObject(message.kernels[j], options);
            }
            if (message.timestamp != null && message.hasOwnProperty("timestamp"))
                if (typeof message.timestamp === "number")
                    object.timestamp = options.longs === String ? String(message.timestamp) : message.timestamp;
                else
                    object.timestamp = options.longs === String ? $util.Long.prototype.toString.call(message.timestamp) : options.longs === Number ? new $util.LongBits(message.timestamp.low >>> 0, message.timestamp.high >>> 0).toNumber(true) : message.timestamp;
            if (message.aggregatedRangeProof != null && message.hasOwnProperty("aggregatedRangeProof"))
                object.aggregatedRangeProof = options.bytes === String ? $util.base64.encode(message.aggregatedRangeProof, 0, message.aggregatedRangeProof.length) : options.bytes === Array ? Array.prototype.slice.call(message.aggregatedRangeProof) : message.aggregatedRangeProof;
            return object;
        };

        /**
         * Converts this Transaction to JSON.
         * @function toJSON
         * @memberof p2p.Transaction
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        Transaction.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for Transaction
         * @function getTypeUrl
         * @memberof p2p.Transaction
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        Transaction.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.Transaction";
        };

        return Transaction;
    })();

    p2p.Block = (function() {

        /**
         * Properties of a Block.
         * @memberof p2p
         * @interface IBlock
         * @property {number|Long|null} [height] Block height
         * @property {string|null} [prevHash] Block prevHash
         * @property {number|Long|null} [timestamp] Block timestamp
         * @property {Array.<p2p.ITransaction>|null} [transactions] Block transactions
         * @property {number|Long|null} [lotteryNonce] Block lotteryNonce
         * @property {p2p.IVrfProof|null} [vrfProof] Block vrfProof
         * @property {p2p.IVdfProof|null} [vdfProof] Block vdfProof
         * @property {Uint8Array|null} [minerPubkey] Block minerPubkey
         * @property {Uint8Array|null} [vrfThreshold] Block vrfThreshold
         * @property {number|Long|null} [vdfIterations] Block vdfIterations
         * @property {Uint8Array|null} [txMerkleRoot] Block txMerkleRoot
         * @property {number|Long|null} [totalWork] Block totalWork
         * @property {string|null} [hash] Block hash
         */

        /**
         * Constructs a new Block.
         * @memberof p2p
         * @classdesc Represents a Block.
         * @implements IBlock
         * @constructor
         * @param {p2p.IBlock=} [properties] Properties to set
         */
        function Block(properties) {
            this.transactions = [];
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * Block height.
         * @member {number|Long} height
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.height = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Block prevHash.
         * @member {string} prevHash
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.prevHash = "";

        /**
         * Block timestamp.
         * @member {number|Long} timestamp
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.timestamp = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Block transactions.
         * @member {Array.<p2p.ITransaction>} transactions
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.transactions = $util.emptyArray;

        /**
         * Block lotteryNonce.
         * @member {number|Long} lotteryNonce
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.lotteryNonce = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Block vrfProof.
         * @member {p2p.IVrfProof|null|undefined} vrfProof
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.vrfProof = null;

        /**
         * Block vdfProof.
         * @member {p2p.IVdfProof|null|undefined} vdfProof
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.vdfProof = null;

        /**
         * Block minerPubkey.
         * @member {Uint8Array} minerPubkey
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.minerPubkey = $util.newBuffer([]);

        /**
         * Block vrfThreshold.
         * @member {Uint8Array} vrfThreshold
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.vrfThreshold = $util.newBuffer([]);

        /**
         * Block vdfIterations.
         * @member {number|Long} vdfIterations
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.vdfIterations = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Block txMerkleRoot.
         * @member {Uint8Array} txMerkleRoot
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.txMerkleRoot = $util.newBuffer([]);

        /**
         * Block totalWork.
         * @member {number|Long} totalWork
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.totalWork = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Block hash.
         * @member {string} hash
         * @memberof p2p.Block
         * @instance
         */
        Block.prototype.hash = "";

        /**
         * Creates a new Block instance using the specified properties.
         * @function create
         * @memberof p2p.Block
         * @static
         * @param {p2p.IBlock=} [properties] Properties to set
         * @returns {p2p.Block} Block instance
         */
        Block.create = function create(properties) {
            return new Block(properties);
        };

        /**
         * Encodes the specified Block message. Does not implicitly {@link p2p.Block.verify|verify} messages.
         * @function encode
         * @memberof p2p.Block
         * @static
         * @param {p2p.IBlock} message Block message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        Block.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.height != null && Object.hasOwnProperty.call(message, "height"))
                writer.uint32(/* id 1, wireType 0 =*/8).uint64(message.height);
            if (message.prevHash != null && Object.hasOwnProperty.call(message, "prevHash"))
                writer.uint32(/* id 2, wireType 2 =*/18).string(message.prevHash);
            if (message.timestamp != null && Object.hasOwnProperty.call(message, "timestamp"))
                writer.uint32(/* id 3, wireType 0 =*/24).uint64(message.timestamp);
            if (message.transactions != null && message.transactions.length)
                for (var i = 0; i < message.transactions.length; ++i)
                    $root.p2p.Transaction.encode(message.transactions[i], writer.uint32(/* id 4, wireType 2 =*/34).fork()).ldelim();
            if (message.lotteryNonce != null && Object.hasOwnProperty.call(message, "lotteryNonce"))
                writer.uint32(/* id 5, wireType 0 =*/40).uint64(message.lotteryNonce);
            if (message.vrfProof != null && Object.hasOwnProperty.call(message, "vrfProof"))
                $root.p2p.VrfProof.encode(message.vrfProof, writer.uint32(/* id 6, wireType 2 =*/50).fork()).ldelim();
            if (message.vdfProof != null && Object.hasOwnProperty.call(message, "vdfProof"))
                $root.p2p.VdfProof.encode(message.vdfProof, writer.uint32(/* id 7, wireType 2 =*/58).fork()).ldelim();
            if (message.minerPubkey != null && Object.hasOwnProperty.call(message, "minerPubkey"))
                writer.uint32(/* id 8, wireType 2 =*/66).bytes(message.minerPubkey);
            if (message.vrfThreshold != null && Object.hasOwnProperty.call(message, "vrfThreshold"))
                writer.uint32(/* id 9, wireType 2 =*/74).bytes(message.vrfThreshold);
            if (message.vdfIterations != null && Object.hasOwnProperty.call(message, "vdfIterations"))
                writer.uint32(/* id 10, wireType 0 =*/80).uint64(message.vdfIterations);
            if (message.txMerkleRoot != null && Object.hasOwnProperty.call(message, "txMerkleRoot"))
                writer.uint32(/* id 11, wireType 2 =*/90).bytes(message.txMerkleRoot);
            if (message.totalWork != null && Object.hasOwnProperty.call(message, "totalWork"))
                writer.uint32(/* id 12, wireType 0 =*/96).uint64(message.totalWork);
            if (message.hash != null && Object.hasOwnProperty.call(message, "hash"))
                writer.uint32(/* id 13, wireType 2 =*/106).string(message.hash);
            return writer;
        };

        /**
         * Encodes the specified Block message, length delimited. Does not implicitly {@link p2p.Block.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.Block
         * @static
         * @param {p2p.IBlock} message Block message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        Block.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a Block message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.Block
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.Block} Block
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        Block.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.Block();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.height = reader.uint64();
                        break;
                    }
                case 2: {
                        message.prevHash = reader.string();
                        break;
                    }
                case 3: {
                        message.timestamp = reader.uint64();
                        break;
                    }
                case 4: {
                        if (!(message.transactions && message.transactions.length))
                            message.transactions = [];
                        message.transactions.push($root.p2p.Transaction.decode(reader, reader.uint32()));
                        break;
                    }
                case 5: {
                        message.lotteryNonce = reader.uint64();
                        break;
                    }
                case 6: {
                        message.vrfProof = $root.p2p.VrfProof.decode(reader, reader.uint32());
                        break;
                    }
                case 7: {
                        message.vdfProof = $root.p2p.VdfProof.decode(reader, reader.uint32());
                        break;
                    }
                case 8: {
                        message.minerPubkey = reader.bytes();
                        break;
                    }
                case 9: {
                        message.vrfThreshold = reader.bytes();
                        break;
                    }
                case 10: {
                        message.vdfIterations = reader.uint64();
                        break;
                    }
                case 11: {
                        message.txMerkleRoot = reader.bytes();
                        break;
                    }
                case 12: {
                        message.totalWork = reader.uint64();
                        break;
                    }
                case 13: {
                        message.hash = reader.string();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a Block message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.Block
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.Block} Block
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        Block.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a Block message.
         * @function verify
         * @memberof p2p.Block
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        Block.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.height != null && message.hasOwnProperty("height"))
                if (!$util.isInteger(message.height) && !(message.height && $util.isInteger(message.height.low) && $util.isInteger(message.height.high)))
                    return "height: integer|Long expected";
            if (message.prevHash != null && message.hasOwnProperty("prevHash"))
                if (!$util.isString(message.prevHash))
                    return "prevHash: string expected";
            if (message.timestamp != null && message.hasOwnProperty("timestamp"))
                if (!$util.isInteger(message.timestamp) && !(message.timestamp && $util.isInteger(message.timestamp.low) && $util.isInteger(message.timestamp.high)))
                    return "timestamp: integer|Long expected";
            if (message.transactions != null && message.hasOwnProperty("transactions")) {
                if (!Array.isArray(message.transactions))
                    return "transactions: array expected";
                for (var i = 0; i < message.transactions.length; ++i) {
                    var error = $root.p2p.Transaction.verify(message.transactions[i]);
                    if (error)
                        return "transactions." + error;
                }
            }
            if (message.lotteryNonce != null && message.hasOwnProperty("lotteryNonce"))
                if (!$util.isInteger(message.lotteryNonce) && !(message.lotteryNonce && $util.isInteger(message.lotteryNonce.low) && $util.isInteger(message.lotteryNonce.high)))
                    return "lotteryNonce: integer|Long expected";
            if (message.vrfProof != null && message.hasOwnProperty("vrfProof")) {
                var error = $root.p2p.VrfProof.verify(message.vrfProof);
                if (error)
                    return "vrfProof." + error;
            }
            if (message.vdfProof != null && message.hasOwnProperty("vdfProof")) {
                var error = $root.p2p.VdfProof.verify(message.vdfProof);
                if (error)
                    return "vdfProof." + error;
            }
            if (message.minerPubkey != null && message.hasOwnProperty("minerPubkey"))
                if (!(message.minerPubkey && typeof message.minerPubkey.length === "number" || $util.isString(message.minerPubkey)))
                    return "minerPubkey: buffer expected";
            if (message.vrfThreshold != null && message.hasOwnProperty("vrfThreshold"))
                if (!(message.vrfThreshold && typeof message.vrfThreshold.length === "number" || $util.isString(message.vrfThreshold)))
                    return "vrfThreshold: buffer expected";
            if (message.vdfIterations != null && message.hasOwnProperty("vdfIterations"))
                if (!$util.isInteger(message.vdfIterations) && !(message.vdfIterations && $util.isInteger(message.vdfIterations.low) && $util.isInteger(message.vdfIterations.high)))
                    return "vdfIterations: integer|Long expected";
            if (message.txMerkleRoot != null && message.hasOwnProperty("txMerkleRoot"))
                if (!(message.txMerkleRoot && typeof message.txMerkleRoot.length === "number" || $util.isString(message.txMerkleRoot)))
                    return "txMerkleRoot: buffer expected";
            if (message.totalWork != null && message.hasOwnProperty("totalWork"))
                if (!$util.isInteger(message.totalWork) && !(message.totalWork && $util.isInteger(message.totalWork.low) && $util.isInteger(message.totalWork.high)))
                    return "totalWork: integer|Long expected";
            if (message.hash != null && message.hasOwnProperty("hash"))
                if (!$util.isString(message.hash))
                    return "hash: string expected";
            return null;
        };

        /**
         * Creates a Block message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.Block
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.Block} Block
         */
        Block.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.Block)
                return object;
            var message = new $root.p2p.Block();
            if (object.height != null)
                if ($util.Long)
                    (message.height = $util.Long.fromValue(object.height)).unsigned = true;
                else if (typeof object.height === "string")
                    message.height = parseInt(object.height, 10);
                else if (typeof object.height === "number")
                    message.height = object.height;
                else if (typeof object.height === "object")
                    message.height = new $util.LongBits(object.height.low >>> 0, object.height.high >>> 0).toNumber(true);
            if (object.prevHash != null)
                message.prevHash = String(object.prevHash);
            if (object.timestamp != null)
                if ($util.Long)
                    (message.timestamp = $util.Long.fromValue(object.timestamp)).unsigned = true;
                else if (typeof object.timestamp === "string")
                    message.timestamp = parseInt(object.timestamp, 10);
                else if (typeof object.timestamp === "number")
                    message.timestamp = object.timestamp;
                else if (typeof object.timestamp === "object")
                    message.timestamp = new $util.LongBits(object.timestamp.low >>> 0, object.timestamp.high >>> 0).toNumber(true);
            if (object.transactions) {
                if (!Array.isArray(object.transactions))
                    throw TypeError(".p2p.Block.transactions: array expected");
                message.transactions = [];
                for (var i = 0; i < object.transactions.length; ++i) {
                    if (typeof object.transactions[i] !== "object")
                        throw TypeError(".p2p.Block.transactions: object expected");
                    message.transactions[i] = $root.p2p.Transaction.fromObject(object.transactions[i]);
                }
            }
            if (object.lotteryNonce != null)
                if ($util.Long)
                    (message.lotteryNonce = $util.Long.fromValue(object.lotteryNonce)).unsigned = true;
                else if (typeof object.lotteryNonce === "string")
                    message.lotteryNonce = parseInt(object.lotteryNonce, 10);
                else if (typeof object.lotteryNonce === "number")
                    message.lotteryNonce = object.lotteryNonce;
                else if (typeof object.lotteryNonce === "object")
                    message.lotteryNonce = new $util.LongBits(object.lotteryNonce.low >>> 0, object.lotteryNonce.high >>> 0).toNumber(true);
            if (object.vrfProof != null) {
                if (typeof object.vrfProof !== "object")
                    throw TypeError(".p2p.Block.vrfProof: object expected");
                message.vrfProof = $root.p2p.VrfProof.fromObject(object.vrfProof);
            }
            if (object.vdfProof != null) {
                if (typeof object.vdfProof !== "object")
                    throw TypeError(".p2p.Block.vdfProof: object expected");
                message.vdfProof = $root.p2p.VdfProof.fromObject(object.vdfProof);
            }
            if (object.minerPubkey != null)
                if (typeof object.minerPubkey === "string")
                    $util.base64.decode(object.minerPubkey, message.minerPubkey = $util.newBuffer($util.base64.length(object.minerPubkey)), 0);
                else if (object.minerPubkey.length >= 0)
                    message.minerPubkey = object.minerPubkey;
            if (object.vrfThreshold != null)
                if (typeof object.vrfThreshold === "string")
                    $util.base64.decode(object.vrfThreshold, message.vrfThreshold = $util.newBuffer($util.base64.length(object.vrfThreshold)), 0);
                else if (object.vrfThreshold.length >= 0)
                    message.vrfThreshold = object.vrfThreshold;
            if (object.vdfIterations != null)
                if ($util.Long)
                    (message.vdfIterations = $util.Long.fromValue(object.vdfIterations)).unsigned = true;
                else if (typeof object.vdfIterations === "string")
                    message.vdfIterations = parseInt(object.vdfIterations, 10);
                else if (typeof object.vdfIterations === "number")
                    message.vdfIterations = object.vdfIterations;
                else if (typeof object.vdfIterations === "object")
                    message.vdfIterations = new $util.LongBits(object.vdfIterations.low >>> 0, object.vdfIterations.high >>> 0).toNumber(true);
            if (object.txMerkleRoot != null)
                if (typeof object.txMerkleRoot === "string")
                    $util.base64.decode(object.txMerkleRoot, message.txMerkleRoot = $util.newBuffer($util.base64.length(object.txMerkleRoot)), 0);
                else if (object.txMerkleRoot.length >= 0)
                    message.txMerkleRoot = object.txMerkleRoot;
            if (object.totalWork != null)
                if ($util.Long)
                    (message.totalWork = $util.Long.fromValue(object.totalWork)).unsigned = true;
                else if (typeof object.totalWork === "string")
                    message.totalWork = parseInt(object.totalWork, 10);
                else if (typeof object.totalWork === "number")
                    message.totalWork = object.totalWork;
                else if (typeof object.totalWork === "object")
                    message.totalWork = new $util.LongBits(object.totalWork.low >>> 0, object.totalWork.high >>> 0).toNumber(true);
            if (object.hash != null)
                message.hash = String(object.hash);
            return message;
        };

        /**
         * Creates a plain object from a Block message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.Block
         * @static
         * @param {p2p.Block} message Block
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        Block.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.arrays || options.defaults)
                object.transactions = [];
            if (options.defaults) {
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.height = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.height = options.longs === String ? "0" : 0;
                object.prevHash = "";
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.timestamp = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.timestamp = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.lotteryNonce = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.lotteryNonce = options.longs === String ? "0" : 0;
                object.vrfProof = null;
                object.vdfProof = null;
                if (options.bytes === String)
                    object.minerPubkey = "";
                else {
                    object.minerPubkey = [];
                    if (options.bytes !== Array)
                        object.minerPubkey = $util.newBuffer(object.minerPubkey);
                }
                if (options.bytes === String)
                    object.vrfThreshold = "";
                else {
                    object.vrfThreshold = [];
                    if (options.bytes !== Array)
                        object.vrfThreshold = $util.newBuffer(object.vrfThreshold);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.vdfIterations = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.vdfIterations = options.longs === String ? "0" : 0;
                if (options.bytes === String)
                    object.txMerkleRoot = "";
                else {
                    object.txMerkleRoot = [];
                    if (options.bytes !== Array)
                        object.txMerkleRoot = $util.newBuffer(object.txMerkleRoot);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.totalWork = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.totalWork = options.longs === String ? "0" : 0;
                object.hash = "";
            }
            if (message.height != null && message.hasOwnProperty("height"))
                if (typeof message.height === "number")
                    object.height = options.longs === String ? String(message.height) : message.height;
                else
                    object.height = options.longs === String ? $util.Long.prototype.toString.call(message.height) : options.longs === Number ? new $util.LongBits(message.height.low >>> 0, message.height.high >>> 0).toNumber(true) : message.height;
            if (message.prevHash != null && message.hasOwnProperty("prevHash"))
                object.prevHash = message.prevHash;
            if (message.timestamp != null && message.hasOwnProperty("timestamp"))
                if (typeof message.timestamp === "number")
                    object.timestamp = options.longs === String ? String(message.timestamp) : message.timestamp;
                else
                    object.timestamp = options.longs === String ? $util.Long.prototype.toString.call(message.timestamp) : options.longs === Number ? new $util.LongBits(message.timestamp.low >>> 0, message.timestamp.high >>> 0).toNumber(true) : message.timestamp;
            if (message.transactions && message.transactions.length) {
                object.transactions = [];
                for (var j = 0; j < message.transactions.length; ++j)
                    object.transactions[j] = $root.p2p.Transaction.toObject(message.transactions[j], options);
            }
            if (message.lotteryNonce != null && message.hasOwnProperty("lotteryNonce"))
                if (typeof message.lotteryNonce === "number")
                    object.lotteryNonce = options.longs === String ? String(message.lotteryNonce) : message.lotteryNonce;
                else
                    object.lotteryNonce = options.longs === String ? $util.Long.prototype.toString.call(message.lotteryNonce) : options.longs === Number ? new $util.LongBits(message.lotteryNonce.low >>> 0, message.lotteryNonce.high >>> 0).toNumber(true) : message.lotteryNonce;
            if (message.vrfProof != null && message.hasOwnProperty("vrfProof"))
                object.vrfProof = $root.p2p.VrfProof.toObject(message.vrfProof, options);
            if (message.vdfProof != null && message.hasOwnProperty("vdfProof"))
                object.vdfProof = $root.p2p.VdfProof.toObject(message.vdfProof, options);
            if (message.minerPubkey != null && message.hasOwnProperty("minerPubkey"))
                object.minerPubkey = options.bytes === String ? $util.base64.encode(message.minerPubkey, 0, message.minerPubkey.length) : options.bytes === Array ? Array.prototype.slice.call(message.minerPubkey) : message.minerPubkey;
            if (message.vrfThreshold != null && message.hasOwnProperty("vrfThreshold"))
                object.vrfThreshold = options.bytes === String ? $util.base64.encode(message.vrfThreshold, 0, message.vrfThreshold.length) : options.bytes === Array ? Array.prototype.slice.call(message.vrfThreshold) : message.vrfThreshold;
            if (message.vdfIterations != null && message.hasOwnProperty("vdfIterations"))
                if (typeof message.vdfIterations === "number")
                    object.vdfIterations = options.longs === String ? String(message.vdfIterations) : message.vdfIterations;
                else
                    object.vdfIterations = options.longs === String ? $util.Long.prototype.toString.call(message.vdfIterations) : options.longs === Number ? new $util.LongBits(message.vdfIterations.low >>> 0, message.vdfIterations.high >>> 0).toNumber(true) : message.vdfIterations;
            if (message.txMerkleRoot != null && message.hasOwnProperty("txMerkleRoot"))
                object.txMerkleRoot = options.bytes === String ? $util.base64.encode(message.txMerkleRoot, 0, message.txMerkleRoot.length) : options.bytes === Array ? Array.prototype.slice.call(message.txMerkleRoot) : message.txMerkleRoot;
            if (message.totalWork != null && message.hasOwnProperty("totalWork"))
                if (typeof message.totalWork === "number")
                    object.totalWork = options.longs === String ? String(message.totalWork) : message.totalWork;
                else
                    object.totalWork = options.longs === String ? $util.Long.prototype.toString.call(message.totalWork) : options.longs === Number ? new $util.LongBits(message.totalWork.low >>> 0, message.totalWork.high >>> 0).toNumber(true) : message.totalWork;
            if (message.hash != null && message.hasOwnProperty("hash"))
                object.hash = message.hash;
            return object;
        };

        /**
         * Converts this Block to JSON.
         * @function toJSON
         * @memberof p2p.Block
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        Block.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for Block
         * @function getTypeUrl
         * @memberof p2p.Block
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        Block.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.Block";
        };

        return Block;
    })();

    p2p.BlockAnnouncement = (function() {

        /**
         * Properties of a BlockAnnouncement.
         * @memberof p2p
         * @interface IBlockAnnouncement
         * @property {string|null} [hash] BlockAnnouncement hash
         * @property {number|Long|null} [height] BlockAnnouncement height
         */

        /**
         * Constructs a new BlockAnnouncement.
         * @memberof p2p
         * @classdesc Represents a BlockAnnouncement.
         * @implements IBlockAnnouncement
         * @constructor
         * @param {p2p.IBlockAnnouncement=} [properties] Properties to set
         */
        function BlockAnnouncement(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * BlockAnnouncement hash.
         * @member {string} hash
         * @memberof p2p.BlockAnnouncement
         * @instance
         */
        BlockAnnouncement.prototype.hash = "";

        /**
         * BlockAnnouncement height.
         * @member {number|Long} height
         * @memberof p2p.BlockAnnouncement
         * @instance
         */
        BlockAnnouncement.prototype.height = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Creates a new BlockAnnouncement instance using the specified properties.
         * @function create
         * @memberof p2p.BlockAnnouncement
         * @static
         * @param {p2p.IBlockAnnouncement=} [properties] Properties to set
         * @returns {p2p.BlockAnnouncement} BlockAnnouncement instance
         */
        BlockAnnouncement.create = function create(properties) {
            return new BlockAnnouncement(properties);
        };

        /**
         * Encodes the specified BlockAnnouncement message. Does not implicitly {@link p2p.BlockAnnouncement.verify|verify} messages.
         * @function encode
         * @memberof p2p.BlockAnnouncement
         * @static
         * @param {p2p.IBlockAnnouncement} message BlockAnnouncement message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        BlockAnnouncement.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.hash != null && Object.hasOwnProperty.call(message, "hash"))
                writer.uint32(/* id 1, wireType 2 =*/10).string(message.hash);
            if (message.height != null && Object.hasOwnProperty.call(message, "height"))
                writer.uint32(/* id 2, wireType 0 =*/16).uint64(message.height);
            return writer;
        };

        /**
         * Encodes the specified BlockAnnouncement message, length delimited. Does not implicitly {@link p2p.BlockAnnouncement.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.BlockAnnouncement
         * @static
         * @param {p2p.IBlockAnnouncement} message BlockAnnouncement message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        BlockAnnouncement.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a BlockAnnouncement message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.BlockAnnouncement
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.BlockAnnouncement} BlockAnnouncement
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        BlockAnnouncement.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.BlockAnnouncement();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.hash = reader.string();
                        break;
                    }
                case 2: {
                        message.height = reader.uint64();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a BlockAnnouncement message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.BlockAnnouncement
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.BlockAnnouncement} BlockAnnouncement
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        BlockAnnouncement.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a BlockAnnouncement message.
         * @function verify
         * @memberof p2p.BlockAnnouncement
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        BlockAnnouncement.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.hash != null && message.hasOwnProperty("hash"))
                if (!$util.isString(message.hash))
                    return "hash: string expected";
            if (message.height != null && message.hasOwnProperty("height"))
                if (!$util.isInteger(message.height) && !(message.height && $util.isInteger(message.height.low) && $util.isInteger(message.height.high)))
                    return "height: integer|Long expected";
            return null;
        };

        /**
         * Creates a BlockAnnouncement message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.BlockAnnouncement
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.BlockAnnouncement} BlockAnnouncement
         */
        BlockAnnouncement.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.BlockAnnouncement)
                return object;
            var message = new $root.p2p.BlockAnnouncement();
            if (object.hash != null)
                message.hash = String(object.hash);
            if (object.height != null)
                if ($util.Long)
                    (message.height = $util.Long.fromValue(object.height)).unsigned = true;
                else if (typeof object.height === "string")
                    message.height = parseInt(object.height, 10);
                else if (typeof object.height === "number")
                    message.height = object.height;
                else if (typeof object.height === "object")
                    message.height = new $util.LongBits(object.height.low >>> 0, object.height.high >>> 0).toNumber(true);
            return message;
        };

        /**
         * Creates a plain object from a BlockAnnouncement message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.BlockAnnouncement
         * @static
         * @param {p2p.BlockAnnouncement} message BlockAnnouncement
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        BlockAnnouncement.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                object.hash = "";
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.height = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.height = options.longs === String ? "0" : 0;
            }
            if (message.hash != null && message.hasOwnProperty("hash"))
                object.hash = message.hash;
            if (message.height != null && message.hasOwnProperty("height"))
                if (typeof message.height === "number")
                    object.height = options.longs === String ? String(message.height) : message.height;
                else
                    object.height = options.longs === String ? $util.Long.prototype.toString.call(message.height) : options.longs === Number ? new $util.LongBits(message.height.low >>> 0, message.height.high >>> 0).toNumber(true) : message.height;
            return object;
        };

        /**
         * Converts this BlockAnnouncement to JSON.
         * @function toJSON
         * @memberof p2p.BlockAnnouncement
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        BlockAnnouncement.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for BlockAnnouncement
         * @function getTypeUrl
         * @memberof p2p.BlockAnnouncement
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        BlockAnnouncement.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.BlockAnnouncement";
        };

        return BlockAnnouncement;
    })();

    p2p.BlockRequest = (function() {

        /**
         * Properties of a BlockRequest.
         * @memberof p2p
         * @interface IBlockRequest
         * @property {string|null} [hash] BlockRequest hash
         */

        /**
         * Constructs a new BlockRequest.
         * @memberof p2p
         * @classdesc Represents a BlockRequest.
         * @implements IBlockRequest
         * @constructor
         * @param {p2p.IBlockRequest=} [properties] Properties to set
         */
        function BlockRequest(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * BlockRequest hash.
         * @member {string} hash
         * @memberof p2p.BlockRequest
         * @instance
         */
        BlockRequest.prototype.hash = "";

        /**
         * Creates a new BlockRequest instance using the specified properties.
         * @function create
         * @memberof p2p.BlockRequest
         * @static
         * @param {p2p.IBlockRequest=} [properties] Properties to set
         * @returns {p2p.BlockRequest} BlockRequest instance
         */
        BlockRequest.create = function create(properties) {
            return new BlockRequest(properties);
        };

        /**
         * Encodes the specified BlockRequest message. Does not implicitly {@link p2p.BlockRequest.verify|verify} messages.
         * @function encode
         * @memberof p2p.BlockRequest
         * @static
         * @param {p2p.IBlockRequest} message BlockRequest message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        BlockRequest.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.hash != null && Object.hasOwnProperty.call(message, "hash"))
                writer.uint32(/* id 1, wireType 2 =*/10).string(message.hash);
            return writer;
        };

        /**
         * Encodes the specified BlockRequest message, length delimited. Does not implicitly {@link p2p.BlockRequest.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.BlockRequest
         * @static
         * @param {p2p.IBlockRequest} message BlockRequest message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        BlockRequest.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a BlockRequest message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.BlockRequest
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.BlockRequest} BlockRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        BlockRequest.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.BlockRequest();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.hash = reader.string();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a BlockRequest message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.BlockRequest
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.BlockRequest} BlockRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        BlockRequest.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a BlockRequest message.
         * @function verify
         * @memberof p2p.BlockRequest
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        BlockRequest.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.hash != null && message.hasOwnProperty("hash"))
                if (!$util.isString(message.hash))
                    return "hash: string expected";
            return null;
        };

        /**
         * Creates a BlockRequest message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.BlockRequest
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.BlockRequest} BlockRequest
         */
        BlockRequest.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.BlockRequest)
                return object;
            var message = new $root.p2p.BlockRequest();
            if (object.hash != null)
                message.hash = String(object.hash);
            return message;
        };

        /**
         * Creates a plain object from a BlockRequest message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.BlockRequest
         * @static
         * @param {p2p.BlockRequest} message BlockRequest
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        BlockRequest.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults)
                object.hash = "";
            if (message.hash != null && message.hasOwnProperty("hash"))
                object.hash = message.hash;
            return object;
        };

        /**
         * Converts this BlockRequest to JSON.
         * @function toJSON
         * @memberof p2p.BlockRequest
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        BlockRequest.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for BlockRequest
         * @function getTypeUrl
         * @memberof p2p.BlockRequest
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        BlockRequest.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.BlockRequest";
        };

        return BlockRequest;
    })();

    p2p.GetHashesRequest = (function() {

        /**
         * Properties of a GetHashesRequest.
         * @memberof p2p
         * @interface IGetHashesRequest
         * @property {number|Long|null} [startHeight] GetHashesRequest startHeight
         * @property {string|null} [requestId] GetHashesRequest requestId
         */

        /**
         * Constructs a new GetHashesRequest.
         * @memberof p2p
         * @classdesc Represents a GetHashesRequest.
         * @implements IGetHashesRequest
         * @constructor
         * @param {p2p.IGetHashesRequest=} [properties] Properties to set
         */
        function GetHashesRequest(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * GetHashesRequest startHeight.
         * @member {number|Long} startHeight
         * @memberof p2p.GetHashesRequest
         * @instance
         */
        GetHashesRequest.prototype.startHeight = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * GetHashesRequest requestId.
         * @member {string} requestId
         * @memberof p2p.GetHashesRequest
         * @instance
         */
        GetHashesRequest.prototype.requestId = "";

        /**
         * Creates a new GetHashesRequest instance using the specified properties.
         * @function create
         * @memberof p2p.GetHashesRequest
         * @static
         * @param {p2p.IGetHashesRequest=} [properties] Properties to set
         * @returns {p2p.GetHashesRequest} GetHashesRequest instance
         */
        GetHashesRequest.create = function create(properties) {
            return new GetHashesRequest(properties);
        };

        /**
         * Encodes the specified GetHashesRequest message. Does not implicitly {@link p2p.GetHashesRequest.verify|verify} messages.
         * @function encode
         * @memberof p2p.GetHashesRequest
         * @static
         * @param {p2p.IGetHashesRequest} message GetHashesRequest message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        GetHashesRequest.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.startHeight != null && Object.hasOwnProperty.call(message, "startHeight"))
                writer.uint32(/* id 1, wireType 0 =*/8).uint64(message.startHeight);
            if (message.requestId != null && Object.hasOwnProperty.call(message, "requestId"))
                writer.uint32(/* id 2, wireType 2 =*/18).string(message.requestId);
            return writer;
        };

        /**
         * Encodes the specified GetHashesRequest message, length delimited. Does not implicitly {@link p2p.GetHashesRequest.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.GetHashesRequest
         * @static
         * @param {p2p.IGetHashesRequest} message GetHashesRequest message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        GetHashesRequest.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a GetHashesRequest message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.GetHashesRequest
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.GetHashesRequest} GetHashesRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        GetHashesRequest.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.GetHashesRequest();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.startHeight = reader.uint64();
                        break;
                    }
                case 2: {
                        message.requestId = reader.string();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a GetHashesRequest message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.GetHashesRequest
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.GetHashesRequest} GetHashesRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        GetHashesRequest.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a GetHashesRequest message.
         * @function verify
         * @memberof p2p.GetHashesRequest
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        GetHashesRequest.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.startHeight != null && message.hasOwnProperty("startHeight"))
                if (!$util.isInteger(message.startHeight) && !(message.startHeight && $util.isInteger(message.startHeight.low) && $util.isInteger(message.startHeight.high)))
                    return "startHeight: integer|Long expected";
            if (message.requestId != null && message.hasOwnProperty("requestId"))
                if (!$util.isString(message.requestId))
                    return "requestId: string expected";
            return null;
        };

        /**
         * Creates a GetHashesRequest message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.GetHashesRequest
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.GetHashesRequest} GetHashesRequest
         */
        GetHashesRequest.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.GetHashesRequest)
                return object;
            var message = new $root.p2p.GetHashesRequest();
            if (object.startHeight != null)
                if ($util.Long)
                    (message.startHeight = $util.Long.fromValue(object.startHeight)).unsigned = true;
                else if (typeof object.startHeight === "string")
                    message.startHeight = parseInt(object.startHeight, 10);
                else if (typeof object.startHeight === "number")
                    message.startHeight = object.startHeight;
                else if (typeof object.startHeight === "object")
                    message.startHeight = new $util.LongBits(object.startHeight.low >>> 0, object.startHeight.high >>> 0).toNumber(true);
            if (object.requestId != null)
                message.requestId = String(object.requestId);
            return message;
        };

        /**
         * Creates a plain object from a GetHashesRequest message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.GetHashesRequest
         * @static
         * @param {p2p.GetHashesRequest} message GetHashesRequest
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        GetHashesRequest.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.startHeight = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.startHeight = options.longs === String ? "0" : 0;
                object.requestId = "";
            }
            if (message.startHeight != null && message.hasOwnProperty("startHeight"))
                if (typeof message.startHeight === "number")
                    object.startHeight = options.longs === String ? String(message.startHeight) : message.startHeight;
                else
                    object.startHeight = options.longs === String ? $util.Long.prototype.toString.call(message.startHeight) : options.longs === Number ? new $util.LongBits(message.startHeight.low >>> 0, message.startHeight.high >>> 0).toNumber(true) : message.startHeight;
            if (message.requestId != null && message.hasOwnProperty("requestId"))
                object.requestId = message.requestId;
            return object;
        };

        /**
         * Converts this GetHashesRequest to JSON.
         * @function toJSON
         * @memberof p2p.GetHashesRequest
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        GetHashesRequest.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for GetHashesRequest
         * @function getTypeUrl
         * @memberof p2p.GetHashesRequest
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        GetHashesRequest.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.GetHashesRequest";
        };

        return GetHashesRequest;
    })();

    p2p.HashesResponse = (function() {

        /**
         * Properties of a HashesResponse.
         * @memberof p2p
         * @interface IHashesResponse
         * @property {Array.<string>|null} [hashes] HashesResponse hashes
         * @property {string|null} [requestId] HashesResponse requestId
         * @property {boolean|null} [finalChunk] HashesResponse finalChunk
         */

        /**
         * Constructs a new HashesResponse.
         * @memberof p2p
         * @classdesc Represents a HashesResponse.
         * @implements IHashesResponse
         * @constructor
         * @param {p2p.IHashesResponse=} [properties] Properties to set
         */
        function HashesResponse(properties) {
            this.hashes = [];
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * HashesResponse hashes.
         * @member {Array.<string>} hashes
         * @memberof p2p.HashesResponse
         * @instance
         */
        HashesResponse.prototype.hashes = $util.emptyArray;

        /**
         * HashesResponse requestId.
         * @member {string} requestId
         * @memberof p2p.HashesResponse
         * @instance
         */
        HashesResponse.prototype.requestId = "";

        /**
         * HashesResponse finalChunk.
         * @member {boolean} finalChunk
         * @memberof p2p.HashesResponse
         * @instance
         */
        HashesResponse.prototype.finalChunk = false;

        /**
         * Creates a new HashesResponse instance using the specified properties.
         * @function create
         * @memberof p2p.HashesResponse
         * @static
         * @param {p2p.IHashesResponse=} [properties] Properties to set
         * @returns {p2p.HashesResponse} HashesResponse instance
         */
        HashesResponse.create = function create(properties) {
            return new HashesResponse(properties);
        };

        /**
         * Encodes the specified HashesResponse message. Does not implicitly {@link p2p.HashesResponse.verify|verify} messages.
         * @function encode
         * @memberof p2p.HashesResponse
         * @static
         * @param {p2p.IHashesResponse} message HashesResponse message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        HashesResponse.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.hashes != null && message.hashes.length)
                for (var i = 0; i < message.hashes.length; ++i)
                    writer.uint32(/* id 1, wireType 2 =*/10).string(message.hashes[i]);
            if (message.requestId != null && Object.hasOwnProperty.call(message, "requestId"))
                writer.uint32(/* id 2, wireType 2 =*/18).string(message.requestId);
            if (message.finalChunk != null && Object.hasOwnProperty.call(message, "finalChunk"))
                writer.uint32(/* id 3, wireType 0 =*/24).bool(message.finalChunk);
            return writer;
        };

        /**
         * Encodes the specified HashesResponse message, length delimited. Does not implicitly {@link p2p.HashesResponse.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.HashesResponse
         * @static
         * @param {p2p.IHashesResponse} message HashesResponse message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        HashesResponse.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a HashesResponse message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.HashesResponse
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.HashesResponse} HashesResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        HashesResponse.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.HashesResponse();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        if (!(message.hashes && message.hashes.length))
                            message.hashes = [];
                        message.hashes.push(reader.string());
                        break;
                    }
                case 2: {
                        message.requestId = reader.string();
                        break;
                    }
                case 3: {
                        message.finalChunk = reader.bool();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a HashesResponse message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.HashesResponse
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.HashesResponse} HashesResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        HashesResponse.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a HashesResponse message.
         * @function verify
         * @memberof p2p.HashesResponse
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        HashesResponse.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.hashes != null && message.hasOwnProperty("hashes")) {
                if (!Array.isArray(message.hashes))
                    return "hashes: array expected";
                for (var i = 0; i < message.hashes.length; ++i)
                    if (!$util.isString(message.hashes[i]))
                        return "hashes: string[] expected";
            }
            if (message.requestId != null && message.hasOwnProperty("requestId"))
                if (!$util.isString(message.requestId))
                    return "requestId: string expected";
            if (message.finalChunk != null && message.hasOwnProperty("finalChunk"))
                if (typeof message.finalChunk !== "boolean")
                    return "finalChunk: boolean expected";
            return null;
        };

        /**
         * Creates a HashesResponse message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.HashesResponse
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.HashesResponse} HashesResponse
         */
        HashesResponse.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.HashesResponse)
                return object;
            var message = new $root.p2p.HashesResponse();
            if (object.hashes) {
                if (!Array.isArray(object.hashes))
                    throw TypeError(".p2p.HashesResponse.hashes: array expected");
                message.hashes = [];
                for (var i = 0; i < object.hashes.length; ++i)
                    message.hashes[i] = String(object.hashes[i]);
            }
            if (object.requestId != null)
                message.requestId = String(object.requestId);
            if (object.finalChunk != null)
                message.finalChunk = Boolean(object.finalChunk);
            return message;
        };

        /**
         * Creates a plain object from a HashesResponse message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.HashesResponse
         * @static
         * @param {p2p.HashesResponse} message HashesResponse
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        HashesResponse.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.arrays || options.defaults)
                object.hashes = [];
            if (options.defaults) {
                object.requestId = "";
                object.finalChunk = false;
            }
            if (message.hashes && message.hashes.length) {
                object.hashes = [];
                for (var j = 0; j < message.hashes.length; ++j)
                    object.hashes[j] = message.hashes[j];
            }
            if (message.requestId != null && message.hasOwnProperty("requestId"))
                object.requestId = message.requestId;
            if (message.finalChunk != null && message.hasOwnProperty("finalChunk"))
                object.finalChunk = message.finalChunk;
            return object;
        };

        /**
         * Converts this HashesResponse to JSON.
         * @function toJSON
         * @memberof p2p.HashesResponse
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        HashesResponse.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for HashesResponse
         * @function getTypeUrl
         * @memberof p2p.HashesResponse
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        HashesResponse.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.HashesResponse";
        };

        return HashesResponse;
    })();

    p2p.TipRequest = (function() {

        /**
         * Properties of a TipRequest.
         * @memberof p2p
         * @interface ITipRequest
         */

        /**
         * Constructs a new TipRequest.
         * @memberof p2p
         * @classdesc Represents a TipRequest.
         * @implements ITipRequest
         * @constructor
         * @param {p2p.ITipRequest=} [properties] Properties to set
         */
        function TipRequest(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * Creates a new TipRequest instance using the specified properties.
         * @function create
         * @memberof p2p.TipRequest
         * @static
         * @param {p2p.ITipRequest=} [properties] Properties to set
         * @returns {p2p.TipRequest} TipRequest instance
         */
        TipRequest.create = function create(properties) {
            return new TipRequest(properties);
        };

        /**
         * Encodes the specified TipRequest message. Does not implicitly {@link p2p.TipRequest.verify|verify} messages.
         * @function encode
         * @memberof p2p.TipRequest
         * @static
         * @param {p2p.ITipRequest} message TipRequest message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        TipRequest.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            return writer;
        };

        /**
         * Encodes the specified TipRequest message, length delimited. Does not implicitly {@link p2p.TipRequest.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.TipRequest
         * @static
         * @param {p2p.ITipRequest} message TipRequest message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        TipRequest.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a TipRequest message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.TipRequest
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.TipRequest} TipRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        TipRequest.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.TipRequest();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a TipRequest message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.TipRequest
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.TipRequest} TipRequest
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        TipRequest.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a TipRequest message.
         * @function verify
         * @memberof p2p.TipRequest
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        TipRequest.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            return null;
        };

        /**
         * Creates a TipRequest message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.TipRequest
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.TipRequest} TipRequest
         */
        TipRequest.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.TipRequest)
                return object;
            return new $root.p2p.TipRequest();
        };

        /**
         * Creates a plain object from a TipRequest message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.TipRequest
         * @static
         * @param {p2p.TipRequest} message TipRequest
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        TipRequest.toObject = function toObject() {
            return {};
        };

        /**
         * Converts this TipRequest to JSON.
         * @function toJSON
         * @memberof p2p.TipRequest
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        TipRequest.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for TipRequest
         * @function getTypeUrl
         * @memberof p2p.TipRequest
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        TipRequest.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.TipRequest";
        };

        return TipRequest;
    })();

    p2p.TipResponse = (function() {

        /**
         * Properties of a TipResponse.
         * @memberof p2p
         * @interface ITipResponse
         * @property {string|null} [tipHash] TipResponse tipHash
         * @property {number|Long|null} [height] TipResponse height
         * @property {string|null} [totalWork] TipResponse totalWork
         */

        /**
         * Constructs a new TipResponse.
         * @memberof p2p
         * @classdesc Represents a TipResponse.
         * @implements ITipResponse
         * @constructor
         * @param {p2p.ITipResponse=} [properties] Properties to set
         */
        function TipResponse(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * TipResponse tipHash.
         * @member {string} tipHash
         * @memberof p2p.TipResponse
         * @instance
         */
        TipResponse.prototype.tipHash = "";

        /**
         * TipResponse height.
         * @member {number|Long} height
         * @memberof p2p.TipResponse
         * @instance
         */
        TipResponse.prototype.height = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * TipResponse totalWork.
         * @member {string} totalWork
         * @memberof p2p.TipResponse
         * @instance
         */
        TipResponse.prototype.totalWork = "";

        /**
         * Creates a new TipResponse instance using the specified properties.
         * @function create
         * @memberof p2p.TipResponse
         * @static
         * @param {p2p.ITipResponse=} [properties] Properties to set
         * @returns {p2p.TipResponse} TipResponse instance
         */
        TipResponse.create = function create(properties) {
            return new TipResponse(properties);
        };

        /**
         * Encodes the specified TipResponse message. Does not implicitly {@link p2p.TipResponse.verify|verify} messages.
         * @function encode
         * @memberof p2p.TipResponse
         * @static
         * @param {p2p.ITipResponse} message TipResponse message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        TipResponse.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.tipHash != null && Object.hasOwnProperty.call(message, "tipHash"))
                writer.uint32(/* id 1, wireType 2 =*/10).string(message.tipHash);
            if (message.height != null && Object.hasOwnProperty.call(message, "height"))
                writer.uint32(/* id 2, wireType 0 =*/16).uint64(message.height);
            if (message.totalWork != null && Object.hasOwnProperty.call(message, "totalWork"))
                writer.uint32(/* id 3, wireType 2 =*/26).string(message.totalWork);
            return writer;
        };

        /**
         * Encodes the specified TipResponse message, length delimited. Does not implicitly {@link p2p.TipResponse.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.TipResponse
         * @static
         * @param {p2p.ITipResponse} message TipResponse message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        TipResponse.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a TipResponse message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.TipResponse
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.TipResponse} TipResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        TipResponse.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.TipResponse();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.tipHash = reader.string();
                        break;
                    }
                case 2: {
                        message.height = reader.uint64();
                        break;
                    }
                case 3: {
                        message.totalWork = reader.string();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a TipResponse message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.TipResponse
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.TipResponse} TipResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        TipResponse.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a TipResponse message.
         * @function verify
         * @memberof p2p.TipResponse
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        TipResponse.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.tipHash != null && message.hasOwnProperty("tipHash"))
                if (!$util.isString(message.tipHash))
                    return "tipHash: string expected";
            if (message.height != null && message.hasOwnProperty("height"))
                if (!$util.isInteger(message.height) && !(message.height && $util.isInteger(message.height.low) && $util.isInteger(message.height.high)))
                    return "height: integer|Long expected";
            if (message.totalWork != null && message.hasOwnProperty("totalWork"))
                if (!$util.isString(message.totalWork))
                    return "totalWork: string expected";
            return null;
        };

        /**
         * Creates a TipResponse message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.TipResponse
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.TipResponse} TipResponse
         */
        TipResponse.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.TipResponse)
                return object;
            var message = new $root.p2p.TipResponse();
            if (object.tipHash != null)
                message.tipHash = String(object.tipHash);
            if (object.height != null)
                if ($util.Long)
                    (message.height = $util.Long.fromValue(object.height)).unsigned = true;
                else if (typeof object.height === "string")
                    message.height = parseInt(object.height, 10);
                else if (typeof object.height === "number")
                    message.height = object.height;
                else if (typeof object.height === "object")
                    message.height = new $util.LongBits(object.height.low >>> 0, object.height.high >>> 0).toNumber(true);
            if (object.totalWork != null)
                message.totalWork = String(object.totalWork);
            return message;
        };

        /**
         * Creates a plain object from a TipResponse message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.TipResponse
         * @static
         * @param {p2p.TipResponse} message TipResponse
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        TipResponse.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                object.tipHash = "";
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.height = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.height = options.longs === String ? "0" : 0;
                object.totalWork = "";
            }
            if (message.tipHash != null && message.hasOwnProperty("tipHash"))
                object.tipHash = message.tipHash;
            if (message.height != null && message.hasOwnProperty("height"))
                if (typeof message.height === "number")
                    object.height = options.longs === String ? String(message.height) : message.height;
                else
                    object.height = options.longs === String ? $util.Long.prototype.toString.call(message.height) : options.longs === Number ? new $util.LongBits(message.height.low >>> 0, message.height.high >>> 0).toNumber(true) : message.height;
            if (message.totalWork != null && message.hasOwnProperty("totalWork"))
                object.totalWork = message.totalWork;
            return object;
        };

        /**
         * Converts this TipResponse to JSON.
         * @function toJSON
         * @memberof p2p.TipResponse
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        TipResponse.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for TipResponse
         * @function getTypeUrl
         * @memberof p2p.TipResponse
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        TipResponse.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.TipResponse";
        };

        return TipResponse;
    })();

    p2p.SyncMessage = (function() {

        /**
         * Properties of a SyncMessage.
         * @memberof p2p
         * @interface ISyncMessage
         * @property {p2p.ITipRequest|null} [tipRequest] SyncMessage tipRequest
         * @property {p2p.ITipResponse|null} [tipResponse] SyncMessage tipResponse
         */

        /**
         * Constructs a new SyncMessage.
         * @memberof p2p
         * @classdesc Represents a SyncMessage.
         * @implements ISyncMessage
         * @constructor
         * @param {p2p.ISyncMessage=} [properties] Properties to set
         */
        function SyncMessage(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * SyncMessage tipRequest.
         * @member {p2p.ITipRequest|null|undefined} tipRequest
         * @memberof p2p.SyncMessage
         * @instance
         */
        SyncMessage.prototype.tipRequest = null;

        /**
         * SyncMessage tipResponse.
         * @member {p2p.ITipResponse|null|undefined} tipResponse
         * @memberof p2p.SyncMessage
         * @instance
         */
        SyncMessage.prototype.tipResponse = null;

        // OneOf field names bound to virtual getters and setters
        var $oneOfFields;

        /**
         * SyncMessage payload.
         * @member {"tipRequest"|"tipResponse"|undefined} payload
         * @memberof p2p.SyncMessage
         * @instance
         */
        Object.defineProperty(SyncMessage.prototype, "payload", {
            get: $util.oneOfGetter($oneOfFields = ["tipRequest", "tipResponse"]),
            set: $util.oneOfSetter($oneOfFields)
        });

        /**
         * Creates a new SyncMessage instance using the specified properties.
         * @function create
         * @memberof p2p.SyncMessage
         * @static
         * @param {p2p.ISyncMessage=} [properties] Properties to set
         * @returns {p2p.SyncMessage} SyncMessage instance
         */
        SyncMessage.create = function create(properties) {
            return new SyncMessage(properties);
        };

        /**
         * Encodes the specified SyncMessage message. Does not implicitly {@link p2p.SyncMessage.verify|verify} messages.
         * @function encode
         * @memberof p2p.SyncMessage
         * @static
         * @param {p2p.ISyncMessage} message SyncMessage message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        SyncMessage.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.tipRequest != null && Object.hasOwnProperty.call(message, "tipRequest"))
                $root.p2p.TipRequest.encode(message.tipRequest, writer.uint32(/* id 1, wireType 2 =*/10).fork()).ldelim();
            if (message.tipResponse != null && Object.hasOwnProperty.call(message, "tipResponse"))
                $root.p2p.TipResponse.encode(message.tipResponse, writer.uint32(/* id 2, wireType 2 =*/18).fork()).ldelim();
            return writer;
        };

        /**
         * Encodes the specified SyncMessage message, length delimited. Does not implicitly {@link p2p.SyncMessage.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.SyncMessage
         * @static
         * @param {p2p.ISyncMessage} message SyncMessage message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        SyncMessage.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a SyncMessage message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.SyncMessage
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.SyncMessage} SyncMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        SyncMessage.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.SyncMessage();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.tipRequest = $root.p2p.TipRequest.decode(reader, reader.uint32());
                        break;
                    }
                case 2: {
                        message.tipResponse = $root.p2p.TipResponse.decode(reader, reader.uint32());
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a SyncMessage message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.SyncMessage
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.SyncMessage} SyncMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        SyncMessage.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a SyncMessage message.
         * @function verify
         * @memberof p2p.SyncMessage
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        SyncMessage.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            var properties = {};
            if (message.tipRequest != null && message.hasOwnProperty("tipRequest")) {
                properties.payload = 1;
                {
                    var error = $root.p2p.TipRequest.verify(message.tipRequest);
                    if (error)
                        return "tipRequest." + error;
                }
            }
            if (message.tipResponse != null && message.hasOwnProperty("tipResponse")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.TipResponse.verify(message.tipResponse);
                    if (error)
                        return "tipResponse." + error;
                }
            }
            return null;
        };

        /**
         * Creates a SyncMessage message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.SyncMessage
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.SyncMessage} SyncMessage
         */
        SyncMessage.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.SyncMessage)
                return object;
            var message = new $root.p2p.SyncMessage();
            if (object.tipRequest != null) {
                if (typeof object.tipRequest !== "object")
                    throw TypeError(".p2p.SyncMessage.tipRequest: object expected");
                message.tipRequest = $root.p2p.TipRequest.fromObject(object.tipRequest);
            }
            if (object.tipResponse != null) {
                if (typeof object.tipResponse !== "object")
                    throw TypeError(".p2p.SyncMessage.tipResponse: object expected");
                message.tipResponse = $root.p2p.TipResponse.fromObject(object.tipResponse);
            }
            return message;
        };

        /**
         * Creates a plain object from a SyncMessage message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.SyncMessage
         * @static
         * @param {p2p.SyncMessage} message SyncMessage
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        SyncMessage.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (message.tipRequest != null && message.hasOwnProperty("tipRequest")) {
                object.tipRequest = $root.p2p.TipRequest.toObject(message.tipRequest, options);
                if (options.oneofs)
                    object.payload = "tipRequest";
            }
            if (message.tipResponse != null && message.hasOwnProperty("tipResponse")) {
                object.tipResponse = $root.p2p.TipResponse.toObject(message.tipResponse, options);
                if (options.oneofs)
                    object.payload = "tipResponse";
            }
            return object;
        };

        /**
         * Converts this SyncMessage to JSON.
         * @function toJSON
         * @memberof p2p.SyncMessage
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        SyncMessage.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for SyncMessage
         * @function getTypeUrl
         * @memberof p2p.SyncMessage
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        SyncMessage.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.SyncMessage";
        };

        return SyncMessage;
    })();

    p2p.DandelionStem = (function() {

        /**
         * Properties of a DandelionStem.
         * @memberof p2p
         * @interface IDandelionStem
         * @property {p2p.ITransaction|null} [transaction] DandelionStem transaction
         * @property {number|null} [hopCount] DandelionStem hopCount
         * @property {number|Long|null} [timestamp] DandelionStem timestamp
         */

        /**
         * Constructs a new DandelionStem.
         * @memberof p2p
         * @classdesc Represents a DandelionStem.
         * @implements IDandelionStem
         * @constructor
         * @param {p2p.IDandelionStem=} [properties] Properties to set
         */
        function DandelionStem(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * DandelionStem transaction.
         * @member {p2p.ITransaction|null|undefined} transaction
         * @memberof p2p.DandelionStem
         * @instance
         */
        DandelionStem.prototype.transaction = null;

        /**
         * DandelionStem hopCount.
         * @member {number} hopCount
         * @memberof p2p.DandelionStem
         * @instance
         */
        DandelionStem.prototype.hopCount = 0;

        /**
         * DandelionStem timestamp.
         * @member {number|Long} timestamp
         * @memberof p2p.DandelionStem
         * @instance
         */
        DandelionStem.prototype.timestamp = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Creates a new DandelionStem instance using the specified properties.
         * @function create
         * @memberof p2p.DandelionStem
         * @static
         * @param {p2p.IDandelionStem=} [properties] Properties to set
         * @returns {p2p.DandelionStem} DandelionStem instance
         */
        DandelionStem.create = function create(properties) {
            return new DandelionStem(properties);
        };

        /**
         * Encodes the specified DandelionStem message. Does not implicitly {@link p2p.DandelionStem.verify|verify} messages.
         * @function encode
         * @memberof p2p.DandelionStem
         * @static
         * @param {p2p.IDandelionStem} message DandelionStem message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        DandelionStem.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.transaction != null && Object.hasOwnProperty.call(message, "transaction"))
                $root.p2p.Transaction.encode(message.transaction, writer.uint32(/* id 1, wireType 2 =*/10).fork()).ldelim();
            if (message.hopCount != null && Object.hasOwnProperty.call(message, "hopCount"))
                writer.uint32(/* id 2, wireType 0 =*/16).uint32(message.hopCount);
            if (message.timestamp != null && Object.hasOwnProperty.call(message, "timestamp"))
                writer.uint32(/* id 3, wireType 0 =*/24).uint64(message.timestamp);
            return writer;
        };

        /**
         * Encodes the specified DandelionStem message, length delimited. Does not implicitly {@link p2p.DandelionStem.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.DandelionStem
         * @static
         * @param {p2p.IDandelionStem} message DandelionStem message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        DandelionStem.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a DandelionStem message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.DandelionStem
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.DandelionStem} DandelionStem
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        DandelionStem.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.DandelionStem();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.transaction = $root.p2p.Transaction.decode(reader, reader.uint32());
                        break;
                    }
                case 2: {
                        message.hopCount = reader.uint32();
                        break;
                    }
                case 3: {
                        message.timestamp = reader.uint64();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a DandelionStem message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.DandelionStem
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.DandelionStem} DandelionStem
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        DandelionStem.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a DandelionStem message.
         * @function verify
         * @memberof p2p.DandelionStem
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        DandelionStem.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.transaction != null && message.hasOwnProperty("transaction")) {
                var error = $root.p2p.Transaction.verify(message.transaction);
                if (error)
                    return "transaction." + error;
            }
            if (message.hopCount != null && message.hasOwnProperty("hopCount"))
                if (!$util.isInteger(message.hopCount))
                    return "hopCount: integer expected";
            if (message.timestamp != null && message.hasOwnProperty("timestamp"))
                if (!$util.isInteger(message.timestamp) && !(message.timestamp && $util.isInteger(message.timestamp.low) && $util.isInteger(message.timestamp.high)))
                    return "timestamp: integer|Long expected";
            return null;
        };

        /**
         * Creates a DandelionStem message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.DandelionStem
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.DandelionStem} DandelionStem
         */
        DandelionStem.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.DandelionStem)
                return object;
            var message = new $root.p2p.DandelionStem();
            if (object.transaction != null) {
                if (typeof object.transaction !== "object")
                    throw TypeError(".p2p.DandelionStem.transaction: object expected");
                message.transaction = $root.p2p.Transaction.fromObject(object.transaction);
            }
            if (object.hopCount != null)
                message.hopCount = object.hopCount >>> 0;
            if (object.timestamp != null)
                if ($util.Long)
                    (message.timestamp = $util.Long.fromValue(object.timestamp)).unsigned = true;
                else if (typeof object.timestamp === "string")
                    message.timestamp = parseInt(object.timestamp, 10);
                else if (typeof object.timestamp === "number")
                    message.timestamp = object.timestamp;
                else if (typeof object.timestamp === "object")
                    message.timestamp = new $util.LongBits(object.timestamp.low >>> 0, object.timestamp.high >>> 0).toNumber(true);
            return message;
        };

        /**
         * Creates a plain object from a DandelionStem message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.DandelionStem
         * @static
         * @param {p2p.DandelionStem} message DandelionStem
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        DandelionStem.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                object.transaction = null;
                object.hopCount = 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.timestamp = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.timestamp = options.longs === String ? "0" : 0;
            }
            if (message.transaction != null && message.hasOwnProperty("transaction"))
                object.transaction = $root.p2p.Transaction.toObject(message.transaction, options);
            if (message.hopCount != null && message.hasOwnProperty("hopCount"))
                object.hopCount = message.hopCount;
            if (message.timestamp != null && message.hasOwnProperty("timestamp"))
                if (typeof message.timestamp === "number")
                    object.timestamp = options.longs === String ? String(message.timestamp) : message.timestamp;
                else
                    object.timestamp = options.longs === String ? $util.Long.prototype.toString.call(message.timestamp) : options.longs === Number ? new $util.LongBits(message.timestamp.low >>> 0, message.timestamp.high >>> 0).toNumber(true) : message.timestamp;
            return object;
        };

        /**
         * Converts this DandelionStem to JSON.
         * @function toJSON
         * @memberof p2p.DandelionStem
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        DandelionStem.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for DandelionStem
         * @function getTypeUrl
         * @memberof p2p.DandelionStem
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        DandelionStem.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.DandelionStem";
        };

        return DandelionStem;
    })();

    p2p.ReorgMarker = (function() {

        /**
         * Properties of a ReorgMarker.
         * @memberof p2p
         * @interface IReorgMarker
         * @property {number|Long|null} [originalTipHeight] ReorgMarker originalTipHeight
         * @property {number|Long|null} [newTipHeight] ReorgMarker newTipHeight
         * @property {string|null} [newTipHash] ReorgMarker newTipHash
         * @property {Array.<string>|null} [blocksToAttach] ReorgMarker blocksToAttach
         * @property {Array.<number|Long>|null} [blocksToDetachHeights] ReorgMarker blocksToDetachHeights
         * @property {number|Long|null} [timestamp] ReorgMarker timestamp
         */

        /**
         * Constructs a new ReorgMarker.
         * @memberof p2p
         * @classdesc Represents a ReorgMarker.
         * @implements IReorgMarker
         * @constructor
         * @param {p2p.IReorgMarker=} [properties] Properties to set
         */
        function ReorgMarker(properties) {
            this.blocksToAttach = [];
            this.blocksToDetachHeights = [];
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * ReorgMarker originalTipHeight.
         * @member {number|Long} originalTipHeight
         * @memberof p2p.ReorgMarker
         * @instance
         */
        ReorgMarker.prototype.originalTipHeight = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * ReorgMarker newTipHeight.
         * @member {number|Long} newTipHeight
         * @memberof p2p.ReorgMarker
         * @instance
         */
        ReorgMarker.prototype.newTipHeight = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * ReorgMarker newTipHash.
         * @member {string} newTipHash
         * @memberof p2p.ReorgMarker
         * @instance
         */
        ReorgMarker.prototype.newTipHash = "";

        /**
         * ReorgMarker blocksToAttach.
         * @member {Array.<string>} blocksToAttach
         * @memberof p2p.ReorgMarker
         * @instance
         */
        ReorgMarker.prototype.blocksToAttach = $util.emptyArray;

        /**
         * ReorgMarker blocksToDetachHeights.
         * @member {Array.<number|Long>} blocksToDetachHeights
         * @memberof p2p.ReorgMarker
         * @instance
         */
        ReorgMarker.prototype.blocksToDetachHeights = $util.emptyArray;

        /**
         * ReorgMarker timestamp.
         * @member {number|Long} timestamp
         * @memberof p2p.ReorgMarker
         * @instance
         */
        ReorgMarker.prototype.timestamp = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Creates a new ReorgMarker instance using the specified properties.
         * @function create
         * @memberof p2p.ReorgMarker
         * @static
         * @param {p2p.IReorgMarker=} [properties] Properties to set
         * @returns {p2p.ReorgMarker} ReorgMarker instance
         */
        ReorgMarker.create = function create(properties) {
            return new ReorgMarker(properties);
        };

        /**
         * Encodes the specified ReorgMarker message. Does not implicitly {@link p2p.ReorgMarker.verify|verify} messages.
         * @function encode
         * @memberof p2p.ReorgMarker
         * @static
         * @param {p2p.IReorgMarker} message ReorgMarker message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        ReorgMarker.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.originalTipHeight != null && Object.hasOwnProperty.call(message, "originalTipHeight"))
                writer.uint32(/* id 1, wireType 0 =*/8).uint64(message.originalTipHeight);
            if (message.newTipHeight != null && Object.hasOwnProperty.call(message, "newTipHeight"))
                writer.uint32(/* id 2, wireType 0 =*/16).uint64(message.newTipHeight);
            if (message.newTipHash != null && Object.hasOwnProperty.call(message, "newTipHash"))
                writer.uint32(/* id 3, wireType 2 =*/26).string(message.newTipHash);
            if (message.blocksToAttach != null && message.blocksToAttach.length)
                for (var i = 0; i < message.blocksToAttach.length; ++i)
                    writer.uint32(/* id 4, wireType 2 =*/34).string(message.blocksToAttach[i]);
            if (message.blocksToDetachHeights != null && message.blocksToDetachHeights.length) {
                writer.uint32(/* id 5, wireType 2 =*/42).fork();
                for (var i = 0; i < message.blocksToDetachHeights.length; ++i)
                    writer.uint64(message.blocksToDetachHeights[i]);
                writer.ldelim();
            }
            if (message.timestamp != null && Object.hasOwnProperty.call(message, "timestamp"))
                writer.uint32(/* id 6, wireType 0 =*/48).uint64(message.timestamp);
            return writer;
        };

        /**
         * Encodes the specified ReorgMarker message, length delimited. Does not implicitly {@link p2p.ReorgMarker.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.ReorgMarker
         * @static
         * @param {p2p.IReorgMarker} message ReorgMarker message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        ReorgMarker.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a ReorgMarker message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.ReorgMarker
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.ReorgMarker} ReorgMarker
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        ReorgMarker.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.ReorgMarker();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.originalTipHeight = reader.uint64();
                        break;
                    }
                case 2: {
                        message.newTipHeight = reader.uint64();
                        break;
                    }
                case 3: {
                        message.newTipHash = reader.string();
                        break;
                    }
                case 4: {
                        if (!(message.blocksToAttach && message.blocksToAttach.length))
                            message.blocksToAttach = [];
                        message.blocksToAttach.push(reader.string());
                        break;
                    }
                case 5: {
                        if (!(message.blocksToDetachHeights && message.blocksToDetachHeights.length))
                            message.blocksToDetachHeights = [];
                        if ((tag & 7) === 2) {
                            var end2 = reader.uint32() + reader.pos;
                            while (reader.pos < end2)
                                message.blocksToDetachHeights.push(reader.uint64());
                        } else
                            message.blocksToDetachHeights.push(reader.uint64());
                        break;
                    }
                case 6: {
                        message.timestamp = reader.uint64();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a ReorgMarker message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.ReorgMarker
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.ReorgMarker} ReorgMarker
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        ReorgMarker.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a ReorgMarker message.
         * @function verify
         * @memberof p2p.ReorgMarker
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        ReorgMarker.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.originalTipHeight != null && message.hasOwnProperty("originalTipHeight"))
                if (!$util.isInteger(message.originalTipHeight) && !(message.originalTipHeight && $util.isInteger(message.originalTipHeight.low) && $util.isInteger(message.originalTipHeight.high)))
                    return "originalTipHeight: integer|Long expected";
            if (message.newTipHeight != null && message.hasOwnProperty("newTipHeight"))
                if (!$util.isInteger(message.newTipHeight) && !(message.newTipHeight && $util.isInteger(message.newTipHeight.low) && $util.isInteger(message.newTipHeight.high)))
                    return "newTipHeight: integer|Long expected";
            if (message.newTipHash != null && message.hasOwnProperty("newTipHash"))
                if (!$util.isString(message.newTipHash))
                    return "newTipHash: string expected";
            if (message.blocksToAttach != null && message.hasOwnProperty("blocksToAttach")) {
                if (!Array.isArray(message.blocksToAttach))
                    return "blocksToAttach: array expected";
                for (var i = 0; i < message.blocksToAttach.length; ++i)
                    if (!$util.isString(message.blocksToAttach[i]))
                        return "blocksToAttach: string[] expected";
            }
            if (message.blocksToDetachHeights != null && message.hasOwnProperty("blocksToDetachHeights")) {
                if (!Array.isArray(message.blocksToDetachHeights))
                    return "blocksToDetachHeights: array expected";
                for (var i = 0; i < message.blocksToDetachHeights.length; ++i)
                    if (!$util.isInteger(message.blocksToDetachHeights[i]) && !(message.blocksToDetachHeights[i] && $util.isInteger(message.blocksToDetachHeights[i].low) && $util.isInteger(message.blocksToDetachHeights[i].high)))
                        return "blocksToDetachHeights: integer|Long[] expected";
            }
            if (message.timestamp != null && message.hasOwnProperty("timestamp"))
                if (!$util.isInteger(message.timestamp) && !(message.timestamp && $util.isInteger(message.timestamp.low) && $util.isInteger(message.timestamp.high)))
                    return "timestamp: integer|Long expected";
            return null;
        };

        /**
         * Creates a ReorgMarker message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.ReorgMarker
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.ReorgMarker} ReorgMarker
         */
        ReorgMarker.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.ReorgMarker)
                return object;
            var message = new $root.p2p.ReorgMarker();
            if (object.originalTipHeight != null)
                if ($util.Long)
                    (message.originalTipHeight = $util.Long.fromValue(object.originalTipHeight)).unsigned = true;
                else if (typeof object.originalTipHeight === "string")
                    message.originalTipHeight = parseInt(object.originalTipHeight, 10);
                else if (typeof object.originalTipHeight === "number")
                    message.originalTipHeight = object.originalTipHeight;
                else if (typeof object.originalTipHeight === "object")
                    message.originalTipHeight = new $util.LongBits(object.originalTipHeight.low >>> 0, object.originalTipHeight.high >>> 0).toNumber(true);
            if (object.newTipHeight != null)
                if ($util.Long)
                    (message.newTipHeight = $util.Long.fromValue(object.newTipHeight)).unsigned = true;
                else if (typeof object.newTipHeight === "string")
                    message.newTipHeight = parseInt(object.newTipHeight, 10);
                else if (typeof object.newTipHeight === "number")
                    message.newTipHeight = object.newTipHeight;
                else if (typeof object.newTipHeight === "object")
                    message.newTipHeight = new $util.LongBits(object.newTipHeight.low >>> 0, object.newTipHeight.high >>> 0).toNumber(true);
            if (object.newTipHash != null)
                message.newTipHash = String(object.newTipHash);
            if (object.blocksToAttach) {
                if (!Array.isArray(object.blocksToAttach))
                    throw TypeError(".p2p.ReorgMarker.blocksToAttach: array expected");
                message.blocksToAttach = [];
                for (var i = 0; i < object.blocksToAttach.length; ++i)
                    message.blocksToAttach[i] = String(object.blocksToAttach[i]);
            }
            if (object.blocksToDetachHeights) {
                if (!Array.isArray(object.blocksToDetachHeights))
                    throw TypeError(".p2p.ReorgMarker.blocksToDetachHeights: array expected");
                message.blocksToDetachHeights = [];
                for (var i = 0; i < object.blocksToDetachHeights.length; ++i)
                    if ($util.Long)
                        (message.blocksToDetachHeights[i] = $util.Long.fromValue(object.blocksToDetachHeights[i])).unsigned = true;
                    else if (typeof object.blocksToDetachHeights[i] === "string")
                        message.blocksToDetachHeights[i] = parseInt(object.blocksToDetachHeights[i], 10);
                    else if (typeof object.blocksToDetachHeights[i] === "number")
                        message.blocksToDetachHeights[i] = object.blocksToDetachHeights[i];
                    else if (typeof object.blocksToDetachHeights[i] === "object")
                        message.blocksToDetachHeights[i] = new $util.LongBits(object.blocksToDetachHeights[i].low >>> 0, object.blocksToDetachHeights[i].high >>> 0).toNumber(true);
            }
            if (object.timestamp != null)
                if ($util.Long)
                    (message.timestamp = $util.Long.fromValue(object.timestamp)).unsigned = true;
                else if (typeof object.timestamp === "string")
                    message.timestamp = parseInt(object.timestamp, 10);
                else if (typeof object.timestamp === "number")
                    message.timestamp = object.timestamp;
                else if (typeof object.timestamp === "object")
                    message.timestamp = new $util.LongBits(object.timestamp.low >>> 0, object.timestamp.high >>> 0).toNumber(true);
            return message;
        };

        /**
         * Creates a plain object from a ReorgMarker message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.ReorgMarker
         * @static
         * @param {p2p.ReorgMarker} message ReorgMarker
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        ReorgMarker.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.arrays || options.defaults) {
                object.blocksToAttach = [];
                object.blocksToDetachHeights = [];
            }
            if (options.defaults) {
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.originalTipHeight = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.originalTipHeight = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.newTipHeight = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.newTipHeight = options.longs === String ? "0" : 0;
                object.newTipHash = "";
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.timestamp = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.timestamp = options.longs === String ? "0" : 0;
            }
            if (message.originalTipHeight != null && message.hasOwnProperty("originalTipHeight"))
                if (typeof message.originalTipHeight === "number")
                    object.originalTipHeight = options.longs === String ? String(message.originalTipHeight) : message.originalTipHeight;
                else
                    object.originalTipHeight = options.longs === String ? $util.Long.prototype.toString.call(message.originalTipHeight) : options.longs === Number ? new $util.LongBits(message.originalTipHeight.low >>> 0, message.originalTipHeight.high >>> 0).toNumber(true) : message.originalTipHeight;
            if (message.newTipHeight != null && message.hasOwnProperty("newTipHeight"))
                if (typeof message.newTipHeight === "number")
                    object.newTipHeight = options.longs === String ? String(message.newTipHeight) : message.newTipHeight;
                else
                    object.newTipHeight = options.longs === String ? $util.Long.prototype.toString.call(message.newTipHeight) : options.longs === Number ? new $util.LongBits(message.newTipHeight.low >>> 0, message.newTipHeight.high >>> 0).toNumber(true) : message.newTipHeight;
            if (message.newTipHash != null && message.hasOwnProperty("newTipHash"))
                object.newTipHash = message.newTipHash;
            if (message.blocksToAttach && message.blocksToAttach.length) {
                object.blocksToAttach = [];
                for (var j = 0; j < message.blocksToAttach.length; ++j)
                    object.blocksToAttach[j] = message.blocksToAttach[j];
            }
            if (message.blocksToDetachHeights && message.blocksToDetachHeights.length) {
                object.blocksToDetachHeights = [];
                for (var j = 0; j < message.blocksToDetachHeights.length; ++j)
                    if (typeof message.blocksToDetachHeights[j] === "number")
                        object.blocksToDetachHeights[j] = options.longs === String ? String(message.blocksToDetachHeights[j]) : message.blocksToDetachHeights[j];
                    else
                        object.blocksToDetachHeights[j] = options.longs === String ? $util.Long.prototype.toString.call(message.blocksToDetachHeights[j]) : options.longs === Number ? new $util.LongBits(message.blocksToDetachHeights[j].low >>> 0, message.blocksToDetachHeights[j].high >>> 0).toNumber(true) : message.blocksToDetachHeights[j];
            }
            if (message.timestamp != null && message.hasOwnProperty("timestamp"))
                if (typeof message.timestamp === "number")
                    object.timestamp = options.longs === String ? String(message.timestamp) : message.timestamp;
                else
                    object.timestamp = options.longs === String ? $util.Long.prototype.toString.call(message.timestamp) : options.longs === Number ? new $util.LongBits(message.timestamp.low >>> 0, message.timestamp.high >>> 0).toNumber(true) : message.timestamp;
            return object;
        };

        /**
         * Converts this ReorgMarker to JSON.
         * @function toJSON
         * @memberof p2p.ReorgMarker
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        ReorgMarker.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for ReorgMarker
         * @function getTypeUrl
         * @memberof p2p.ReorgMarker
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        ReorgMarker.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.ReorgMarker";
        };

        return ReorgMarker;
    })();

    p2p.AdaptorSignature = (function() {

        /**
         * Properties of an AdaptorSignature.
         * @memberof p2p
         * @interface IAdaptorSignature
         * @property {Uint8Array|null} [publicNonce] AdaptorSignature publicNonce
         * @property {Uint8Array|null} [adaptorPoint] AdaptorSignature adaptorPoint
         * @property {Uint8Array|null} [preSignature] AdaptorSignature preSignature
         * @property {Uint8Array|null} [challenge] AdaptorSignature challenge
         */

        /**
         * Constructs a new AdaptorSignature.
         * @memberof p2p
         * @classdesc Represents an AdaptorSignature.
         * @implements IAdaptorSignature
         * @constructor
         * @param {p2p.IAdaptorSignature=} [properties] Properties to set
         */
        function AdaptorSignature(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * AdaptorSignature publicNonce.
         * @member {Uint8Array} publicNonce
         * @memberof p2p.AdaptorSignature
         * @instance
         */
        AdaptorSignature.prototype.publicNonce = $util.newBuffer([]);

        /**
         * AdaptorSignature adaptorPoint.
         * @member {Uint8Array} adaptorPoint
         * @memberof p2p.AdaptorSignature
         * @instance
         */
        AdaptorSignature.prototype.adaptorPoint = $util.newBuffer([]);

        /**
         * AdaptorSignature preSignature.
         * @member {Uint8Array} preSignature
         * @memberof p2p.AdaptorSignature
         * @instance
         */
        AdaptorSignature.prototype.preSignature = $util.newBuffer([]);

        /**
         * AdaptorSignature challenge.
         * @member {Uint8Array} challenge
         * @memberof p2p.AdaptorSignature
         * @instance
         */
        AdaptorSignature.prototype.challenge = $util.newBuffer([]);

        /**
         * Creates a new AdaptorSignature instance using the specified properties.
         * @function create
         * @memberof p2p.AdaptorSignature
         * @static
         * @param {p2p.IAdaptorSignature=} [properties] Properties to set
         * @returns {p2p.AdaptorSignature} AdaptorSignature instance
         */
        AdaptorSignature.create = function create(properties) {
            return new AdaptorSignature(properties);
        };

        /**
         * Encodes the specified AdaptorSignature message. Does not implicitly {@link p2p.AdaptorSignature.verify|verify} messages.
         * @function encode
         * @memberof p2p.AdaptorSignature
         * @static
         * @param {p2p.IAdaptorSignature} message AdaptorSignature message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        AdaptorSignature.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.publicNonce != null && Object.hasOwnProperty.call(message, "publicNonce"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.publicNonce);
            if (message.adaptorPoint != null && Object.hasOwnProperty.call(message, "adaptorPoint"))
                writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.adaptorPoint);
            if (message.preSignature != null && Object.hasOwnProperty.call(message, "preSignature"))
                writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.preSignature);
            if (message.challenge != null && Object.hasOwnProperty.call(message, "challenge"))
                writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.challenge);
            return writer;
        };

        /**
         * Encodes the specified AdaptorSignature message, length delimited. Does not implicitly {@link p2p.AdaptorSignature.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.AdaptorSignature
         * @static
         * @param {p2p.IAdaptorSignature} message AdaptorSignature message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        AdaptorSignature.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes an AdaptorSignature message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.AdaptorSignature
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.AdaptorSignature} AdaptorSignature
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        AdaptorSignature.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.AdaptorSignature();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.publicNonce = reader.bytes();
                        break;
                    }
                case 2: {
                        message.adaptorPoint = reader.bytes();
                        break;
                    }
                case 3: {
                        message.preSignature = reader.bytes();
                        break;
                    }
                case 4: {
                        message.challenge = reader.bytes();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes an AdaptorSignature message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.AdaptorSignature
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.AdaptorSignature} AdaptorSignature
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        AdaptorSignature.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies an AdaptorSignature message.
         * @function verify
         * @memberof p2p.AdaptorSignature
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        AdaptorSignature.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.publicNonce != null && message.hasOwnProperty("publicNonce"))
                if (!(message.publicNonce && typeof message.publicNonce.length === "number" || $util.isString(message.publicNonce)))
                    return "publicNonce: buffer expected";
            if (message.adaptorPoint != null && message.hasOwnProperty("adaptorPoint"))
                if (!(message.adaptorPoint && typeof message.adaptorPoint.length === "number" || $util.isString(message.adaptorPoint)))
                    return "adaptorPoint: buffer expected";
            if (message.preSignature != null && message.hasOwnProperty("preSignature"))
                if (!(message.preSignature && typeof message.preSignature.length === "number" || $util.isString(message.preSignature)))
                    return "preSignature: buffer expected";
            if (message.challenge != null && message.hasOwnProperty("challenge"))
                if (!(message.challenge && typeof message.challenge.length === "number" || $util.isString(message.challenge)))
                    return "challenge: buffer expected";
            return null;
        };

        /**
         * Creates an AdaptorSignature message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.AdaptorSignature
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.AdaptorSignature} AdaptorSignature
         */
        AdaptorSignature.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.AdaptorSignature)
                return object;
            var message = new $root.p2p.AdaptorSignature();
            if (object.publicNonce != null)
                if (typeof object.publicNonce === "string")
                    $util.base64.decode(object.publicNonce, message.publicNonce = $util.newBuffer($util.base64.length(object.publicNonce)), 0);
                else if (object.publicNonce.length >= 0)
                    message.publicNonce = object.publicNonce;
            if (object.adaptorPoint != null)
                if (typeof object.adaptorPoint === "string")
                    $util.base64.decode(object.adaptorPoint, message.adaptorPoint = $util.newBuffer($util.base64.length(object.adaptorPoint)), 0);
                else if (object.adaptorPoint.length >= 0)
                    message.adaptorPoint = object.adaptorPoint;
            if (object.preSignature != null)
                if (typeof object.preSignature === "string")
                    $util.base64.decode(object.preSignature, message.preSignature = $util.newBuffer($util.base64.length(object.preSignature)), 0);
                else if (object.preSignature.length >= 0)
                    message.preSignature = object.preSignature;
            if (object.challenge != null)
                if (typeof object.challenge === "string")
                    $util.base64.decode(object.challenge, message.challenge = $util.newBuffer($util.base64.length(object.challenge)), 0);
                else if (object.challenge.length >= 0)
                    message.challenge = object.challenge;
            return message;
        };

        /**
         * Creates a plain object from an AdaptorSignature message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.AdaptorSignature
         * @static
         * @param {p2p.AdaptorSignature} message AdaptorSignature
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        AdaptorSignature.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.publicNonce = "";
                else {
                    object.publicNonce = [];
                    if (options.bytes !== Array)
                        object.publicNonce = $util.newBuffer(object.publicNonce);
                }
                if (options.bytes === String)
                    object.adaptorPoint = "";
                else {
                    object.adaptorPoint = [];
                    if (options.bytes !== Array)
                        object.adaptorPoint = $util.newBuffer(object.adaptorPoint);
                }
                if (options.bytes === String)
                    object.preSignature = "";
                else {
                    object.preSignature = [];
                    if (options.bytes !== Array)
                        object.preSignature = $util.newBuffer(object.preSignature);
                }
                if (options.bytes === String)
                    object.challenge = "";
                else {
                    object.challenge = [];
                    if (options.bytes !== Array)
                        object.challenge = $util.newBuffer(object.challenge);
                }
            }
            if (message.publicNonce != null && message.hasOwnProperty("publicNonce"))
                object.publicNonce = options.bytes === String ? $util.base64.encode(message.publicNonce, 0, message.publicNonce.length) : options.bytes === Array ? Array.prototype.slice.call(message.publicNonce) : message.publicNonce;
            if (message.adaptorPoint != null && message.hasOwnProperty("adaptorPoint"))
                object.adaptorPoint = options.bytes === String ? $util.base64.encode(message.adaptorPoint, 0, message.adaptorPoint.length) : options.bytes === Array ? Array.prototype.slice.call(message.adaptorPoint) : message.adaptorPoint;
            if (message.preSignature != null && message.hasOwnProperty("preSignature"))
                object.preSignature = options.bytes === String ? $util.base64.encode(message.preSignature, 0, message.preSignature.length) : options.bytes === Array ? Array.prototype.slice.call(message.preSignature) : message.preSignature;
            if (message.challenge != null && message.hasOwnProperty("challenge"))
                object.challenge = options.bytes === String ? $util.base64.encode(message.challenge, 0, message.challenge.length) : options.bytes === Array ? Array.prototype.slice.call(message.challenge) : message.challenge;
            return object;
        };

        /**
         * Converts this AdaptorSignature to JSON.
         * @function toJSON
         * @memberof p2p.AdaptorSignature
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        AdaptorSignature.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for AdaptorSignature
         * @function getTypeUrl
         * @memberof p2p.AdaptorSignature
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        AdaptorSignature.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.AdaptorSignature";
        };

        return AdaptorSignature;
    })();

    p2p.AtomicSwap = (function() {

        /**
         * Properties of an AtomicSwap.
         * @memberof p2p
         * @interface IAtomicSwap
         * @property {Uint8Array|null} [swapId] AtomicSwap swapId
         * @property {number|Long|null} [stateEnum] AtomicSwap stateEnum
         * @property {number|Long|null} [aliceAmount] AtomicSwap aliceAmount
         * @property {Uint8Array|null} [alicePubkey] AtomicSwap alicePubkey
         * @property {Uint8Array|null} [aliceCommitment] AtomicSwap aliceCommitment
         * @property {p2p.IAdaptorSignature|null} [aliceAdaptorSig] AtomicSwap aliceAdaptorSig
         * @property {number|Long|null} [aliceTimeoutHeight] AtomicSwap aliceTimeoutHeight
         * @property {number|Long|null} [bobAmount] AtomicSwap bobAmount
         * @property {Uint8Array|null} [bobPubkey] AtomicSwap bobPubkey
         * @property {string|null} [bobBtcAddress] AtomicSwap bobBtcAddress
         * @property {string|null} [bobBtcTxid] AtomicSwap bobBtcTxid
         * @property {number|null} [bobBtcVout] AtomicSwap bobBtcVout
         * @property {Uint8Array|null} [bobAdaptorSig] AtomicSwap bobAdaptorSig
         * @property {number|Long|null} [bobTimeoutHeight] AtomicSwap bobTimeoutHeight
         * @property {Uint8Array|null} [sharedAdaptorPoint] AtomicSwap sharedAdaptorPoint
         * @property {Uint8Array|null} [secretHash] AtomicSwap secretHash
         * @property {number|Long|null} [createdAt] AtomicSwap createdAt
         * @property {number|Long|null} [expiresAt] AtomicSwap expiresAt
         * @property {number|Long|null} [lastUpdated] AtomicSwap lastUpdated
         */

        /**
         * Constructs a new AtomicSwap.
         * @memberof p2p
         * @classdesc Represents an AtomicSwap.
         * @implements IAtomicSwap
         * @constructor
         * @param {p2p.IAtomicSwap=} [properties] Properties to set
         */
        function AtomicSwap(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * AtomicSwap swapId.
         * @member {Uint8Array} swapId
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.swapId = $util.newBuffer([]);

        /**
         * AtomicSwap stateEnum.
         * @member {number|Long} stateEnum
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.stateEnum = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * AtomicSwap aliceAmount.
         * @member {number|Long} aliceAmount
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.aliceAmount = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * AtomicSwap alicePubkey.
         * @member {Uint8Array} alicePubkey
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.alicePubkey = $util.newBuffer([]);

        /**
         * AtomicSwap aliceCommitment.
         * @member {Uint8Array} aliceCommitment
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.aliceCommitment = $util.newBuffer([]);

        /**
         * AtomicSwap aliceAdaptorSig.
         * @member {p2p.IAdaptorSignature|null|undefined} aliceAdaptorSig
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.aliceAdaptorSig = null;

        /**
         * AtomicSwap aliceTimeoutHeight.
         * @member {number|Long} aliceTimeoutHeight
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.aliceTimeoutHeight = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * AtomicSwap bobAmount.
         * @member {number|Long} bobAmount
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.bobAmount = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * AtomicSwap bobPubkey.
         * @member {Uint8Array} bobPubkey
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.bobPubkey = $util.newBuffer([]);

        /**
         * AtomicSwap bobBtcAddress.
         * @member {string} bobBtcAddress
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.bobBtcAddress = "";

        /**
         * AtomicSwap bobBtcTxid.
         * @member {string} bobBtcTxid
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.bobBtcTxid = "";

        /**
         * AtomicSwap bobBtcVout.
         * @member {number} bobBtcVout
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.bobBtcVout = 0;

        /**
         * AtomicSwap bobAdaptorSig.
         * @member {Uint8Array} bobAdaptorSig
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.bobAdaptorSig = $util.newBuffer([]);

        /**
         * AtomicSwap bobTimeoutHeight.
         * @member {number|Long} bobTimeoutHeight
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.bobTimeoutHeight = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * AtomicSwap sharedAdaptorPoint.
         * @member {Uint8Array} sharedAdaptorPoint
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.sharedAdaptorPoint = $util.newBuffer([]);

        /**
         * AtomicSwap secretHash.
         * @member {Uint8Array} secretHash
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.secretHash = $util.newBuffer([]);

        /**
         * AtomicSwap createdAt.
         * @member {number|Long} createdAt
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.createdAt = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * AtomicSwap expiresAt.
         * @member {number|Long} expiresAt
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.expiresAt = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * AtomicSwap lastUpdated.
         * @member {number|Long} lastUpdated
         * @memberof p2p.AtomicSwap
         * @instance
         */
        AtomicSwap.prototype.lastUpdated = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        // OneOf field names bound to virtual getters and setters
        var $oneOfFields;

        /**
         * AtomicSwap _aliceAdaptorSig.
         * @member {"aliceAdaptorSig"|undefined} _aliceAdaptorSig
         * @memberof p2p.AtomicSwap
         * @instance
         */
        Object.defineProperty(AtomicSwap.prototype, "_aliceAdaptorSig", {
            get: $util.oneOfGetter($oneOfFields = ["aliceAdaptorSig"]),
            set: $util.oneOfSetter($oneOfFields)
        });

        /**
         * Creates a new AtomicSwap instance using the specified properties.
         * @function create
         * @memberof p2p.AtomicSwap
         * @static
         * @param {p2p.IAtomicSwap=} [properties] Properties to set
         * @returns {p2p.AtomicSwap} AtomicSwap instance
         */
        AtomicSwap.create = function create(properties) {
            return new AtomicSwap(properties);
        };

        /**
         * Encodes the specified AtomicSwap message. Does not implicitly {@link p2p.AtomicSwap.verify|verify} messages.
         * @function encode
         * @memberof p2p.AtomicSwap
         * @static
         * @param {p2p.IAtomicSwap} message AtomicSwap message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        AtomicSwap.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.swapId != null && Object.hasOwnProperty.call(message, "swapId"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.swapId);
            if (message.stateEnum != null && Object.hasOwnProperty.call(message, "stateEnum"))
                writer.uint32(/* id 2, wireType 0 =*/16).uint64(message.stateEnum);
            if (message.aliceAmount != null && Object.hasOwnProperty.call(message, "aliceAmount"))
                writer.uint32(/* id 3, wireType 0 =*/24).uint64(message.aliceAmount);
            if (message.alicePubkey != null && Object.hasOwnProperty.call(message, "alicePubkey"))
                writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.alicePubkey);
            if (message.aliceCommitment != null && Object.hasOwnProperty.call(message, "aliceCommitment"))
                writer.uint32(/* id 5, wireType 2 =*/42).bytes(message.aliceCommitment);
            if (message.aliceAdaptorSig != null && Object.hasOwnProperty.call(message, "aliceAdaptorSig"))
                $root.p2p.AdaptorSignature.encode(message.aliceAdaptorSig, writer.uint32(/* id 6, wireType 2 =*/50).fork()).ldelim();
            if (message.aliceTimeoutHeight != null && Object.hasOwnProperty.call(message, "aliceTimeoutHeight"))
                writer.uint32(/* id 7, wireType 0 =*/56).uint64(message.aliceTimeoutHeight);
            if (message.bobAmount != null && Object.hasOwnProperty.call(message, "bobAmount"))
                writer.uint32(/* id 8, wireType 0 =*/64).uint64(message.bobAmount);
            if (message.bobPubkey != null && Object.hasOwnProperty.call(message, "bobPubkey"))
                writer.uint32(/* id 9, wireType 2 =*/74).bytes(message.bobPubkey);
            if (message.bobBtcAddress != null && Object.hasOwnProperty.call(message, "bobBtcAddress"))
                writer.uint32(/* id 10, wireType 2 =*/82).string(message.bobBtcAddress);
            if (message.bobBtcTxid != null && Object.hasOwnProperty.call(message, "bobBtcTxid"))
                writer.uint32(/* id 11, wireType 2 =*/90).string(message.bobBtcTxid);
            if (message.bobBtcVout != null && Object.hasOwnProperty.call(message, "bobBtcVout"))
                writer.uint32(/* id 12, wireType 0 =*/96).uint32(message.bobBtcVout);
            if (message.bobAdaptorSig != null && Object.hasOwnProperty.call(message, "bobAdaptorSig"))
                writer.uint32(/* id 13, wireType 2 =*/106).bytes(message.bobAdaptorSig);
            if (message.bobTimeoutHeight != null && Object.hasOwnProperty.call(message, "bobTimeoutHeight"))
                writer.uint32(/* id 14, wireType 0 =*/112).uint64(message.bobTimeoutHeight);
            if (message.sharedAdaptorPoint != null && Object.hasOwnProperty.call(message, "sharedAdaptorPoint"))
                writer.uint32(/* id 15, wireType 2 =*/122).bytes(message.sharedAdaptorPoint);
            if (message.secretHash != null && Object.hasOwnProperty.call(message, "secretHash"))
                writer.uint32(/* id 16, wireType 2 =*/130).bytes(message.secretHash);
            if (message.createdAt != null && Object.hasOwnProperty.call(message, "createdAt"))
                writer.uint32(/* id 17, wireType 0 =*/136).uint64(message.createdAt);
            if (message.expiresAt != null && Object.hasOwnProperty.call(message, "expiresAt"))
                writer.uint32(/* id 18, wireType 0 =*/144).uint64(message.expiresAt);
            if (message.lastUpdated != null && Object.hasOwnProperty.call(message, "lastUpdated"))
                writer.uint32(/* id 19, wireType 0 =*/152).uint64(message.lastUpdated);
            return writer;
        };

        /**
         * Encodes the specified AtomicSwap message, length delimited. Does not implicitly {@link p2p.AtomicSwap.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.AtomicSwap
         * @static
         * @param {p2p.IAtomicSwap} message AtomicSwap message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        AtomicSwap.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes an AtomicSwap message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.AtomicSwap
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.AtomicSwap} AtomicSwap
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        AtomicSwap.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.AtomicSwap();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.swapId = reader.bytes();
                        break;
                    }
                case 2: {
                        message.stateEnum = reader.uint64();
                        break;
                    }
                case 3: {
                        message.aliceAmount = reader.uint64();
                        break;
                    }
                case 4: {
                        message.alicePubkey = reader.bytes();
                        break;
                    }
                case 5: {
                        message.aliceCommitment = reader.bytes();
                        break;
                    }
                case 6: {
                        message.aliceAdaptorSig = $root.p2p.AdaptorSignature.decode(reader, reader.uint32());
                        break;
                    }
                case 7: {
                        message.aliceTimeoutHeight = reader.uint64();
                        break;
                    }
                case 8: {
                        message.bobAmount = reader.uint64();
                        break;
                    }
                case 9: {
                        message.bobPubkey = reader.bytes();
                        break;
                    }
                case 10: {
                        message.bobBtcAddress = reader.string();
                        break;
                    }
                case 11: {
                        message.bobBtcTxid = reader.string();
                        break;
                    }
                case 12: {
                        message.bobBtcVout = reader.uint32();
                        break;
                    }
                case 13: {
                        message.bobAdaptorSig = reader.bytes();
                        break;
                    }
                case 14: {
                        message.bobTimeoutHeight = reader.uint64();
                        break;
                    }
                case 15: {
                        message.sharedAdaptorPoint = reader.bytes();
                        break;
                    }
                case 16: {
                        message.secretHash = reader.bytes();
                        break;
                    }
                case 17: {
                        message.createdAt = reader.uint64();
                        break;
                    }
                case 18: {
                        message.expiresAt = reader.uint64();
                        break;
                    }
                case 19: {
                        message.lastUpdated = reader.uint64();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes an AtomicSwap message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.AtomicSwap
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.AtomicSwap} AtomicSwap
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        AtomicSwap.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies an AtomicSwap message.
         * @function verify
         * @memberof p2p.AtomicSwap
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        AtomicSwap.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            var properties = {};
            if (message.swapId != null && message.hasOwnProperty("swapId"))
                if (!(message.swapId && typeof message.swapId.length === "number" || $util.isString(message.swapId)))
                    return "swapId: buffer expected";
            if (message.stateEnum != null && message.hasOwnProperty("stateEnum"))
                if (!$util.isInteger(message.stateEnum) && !(message.stateEnum && $util.isInteger(message.stateEnum.low) && $util.isInteger(message.stateEnum.high)))
                    return "stateEnum: integer|Long expected";
            if (message.aliceAmount != null && message.hasOwnProperty("aliceAmount"))
                if (!$util.isInteger(message.aliceAmount) && !(message.aliceAmount && $util.isInteger(message.aliceAmount.low) && $util.isInteger(message.aliceAmount.high)))
                    return "aliceAmount: integer|Long expected";
            if (message.alicePubkey != null && message.hasOwnProperty("alicePubkey"))
                if (!(message.alicePubkey && typeof message.alicePubkey.length === "number" || $util.isString(message.alicePubkey)))
                    return "alicePubkey: buffer expected";
            if (message.aliceCommitment != null && message.hasOwnProperty("aliceCommitment"))
                if (!(message.aliceCommitment && typeof message.aliceCommitment.length === "number" || $util.isString(message.aliceCommitment)))
                    return "aliceCommitment: buffer expected";
            if (message.aliceAdaptorSig != null && message.hasOwnProperty("aliceAdaptorSig")) {
                properties._aliceAdaptorSig = 1;
                {
                    var error = $root.p2p.AdaptorSignature.verify(message.aliceAdaptorSig);
                    if (error)
                        return "aliceAdaptorSig." + error;
                }
            }
            if (message.aliceTimeoutHeight != null && message.hasOwnProperty("aliceTimeoutHeight"))
                if (!$util.isInteger(message.aliceTimeoutHeight) && !(message.aliceTimeoutHeight && $util.isInteger(message.aliceTimeoutHeight.low) && $util.isInteger(message.aliceTimeoutHeight.high)))
                    return "aliceTimeoutHeight: integer|Long expected";
            if (message.bobAmount != null && message.hasOwnProperty("bobAmount"))
                if (!$util.isInteger(message.bobAmount) && !(message.bobAmount && $util.isInteger(message.bobAmount.low) && $util.isInteger(message.bobAmount.high)))
                    return "bobAmount: integer|Long expected";
            if (message.bobPubkey != null && message.hasOwnProperty("bobPubkey"))
                if (!(message.bobPubkey && typeof message.bobPubkey.length === "number" || $util.isString(message.bobPubkey)))
                    return "bobPubkey: buffer expected";
            if (message.bobBtcAddress != null && message.hasOwnProperty("bobBtcAddress"))
                if (!$util.isString(message.bobBtcAddress))
                    return "bobBtcAddress: string expected";
            if (message.bobBtcTxid != null && message.hasOwnProperty("bobBtcTxid"))
                if (!$util.isString(message.bobBtcTxid))
                    return "bobBtcTxid: string expected";
            if (message.bobBtcVout != null && message.hasOwnProperty("bobBtcVout"))
                if (!$util.isInteger(message.bobBtcVout))
                    return "bobBtcVout: integer expected";
            if (message.bobAdaptorSig != null && message.hasOwnProperty("bobAdaptorSig"))
                if (!(message.bobAdaptorSig && typeof message.bobAdaptorSig.length === "number" || $util.isString(message.bobAdaptorSig)))
                    return "bobAdaptorSig: buffer expected";
            if (message.bobTimeoutHeight != null && message.hasOwnProperty("bobTimeoutHeight"))
                if (!$util.isInteger(message.bobTimeoutHeight) && !(message.bobTimeoutHeight && $util.isInteger(message.bobTimeoutHeight.low) && $util.isInteger(message.bobTimeoutHeight.high)))
                    return "bobTimeoutHeight: integer|Long expected";
            if (message.sharedAdaptorPoint != null && message.hasOwnProperty("sharedAdaptorPoint"))
                if (!(message.sharedAdaptorPoint && typeof message.sharedAdaptorPoint.length === "number" || $util.isString(message.sharedAdaptorPoint)))
                    return "sharedAdaptorPoint: buffer expected";
            if (message.secretHash != null && message.hasOwnProperty("secretHash"))
                if (!(message.secretHash && typeof message.secretHash.length === "number" || $util.isString(message.secretHash)))
                    return "secretHash: buffer expected";
            if (message.createdAt != null && message.hasOwnProperty("createdAt"))
                if (!$util.isInteger(message.createdAt) && !(message.createdAt && $util.isInteger(message.createdAt.low) && $util.isInteger(message.createdAt.high)))
                    return "createdAt: integer|Long expected";
            if (message.expiresAt != null && message.hasOwnProperty("expiresAt"))
                if (!$util.isInteger(message.expiresAt) && !(message.expiresAt && $util.isInteger(message.expiresAt.low) && $util.isInteger(message.expiresAt.high)))
                    return "expiresAt: integer|Long expected";
            if (message.lastUpdated != null && message.hasOwnProperty("lastUpdated"))
                if (!$util.isInteger(message.lastUpdated) && !(message.lastUpdated && $util.isInteger(message.lastUpdated.low) && $util.isInteger(message.lastUpdated.high)))
                    return "lastUpdated: integer|Long expected";
            return null;
        };

        /**
         * Creates an AtomicSwap message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.AtomicSwap
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.AtomicSwap} AtomicSwap
         */
        AtomicSwap.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.AtomicSwap)
                return object;
            var message = new $root.p2p.AtomicSwap();
            if (object.swapId != null)
                if (typeof object.swapId === "string")
                    $util.base64.decode(object.swapId, message.swapId = $util.newBuffer($util.base64.length(object.swapId)), 0);
                else if (object.swapId.length >= 0)
                    message.swapId = object.swapId;
            if (object.stateEnum != null)
                if ($util.Long)
                    (message.stateEnum = $util.Long.fromValue(object.stateEnum)).unsigned = true;
                else if (typeof object.stateEnum === "string")
                    message.stateEnum = parseInt(object.stateEnum, 10);
                else if (typeof object.stateEnum === "number")
                    message.stateEnum = object.stateEnum;
                else if (typeof object.stateEnum === "object")
                    message.stateEnum = new $util.LongBits(object.stateEnum.low >>> 0, object.stateEnum.high >>> 0).toNumber(true);
            if (object.aliceAmount != null)
                if ($util.Long)
                    (message.aliceAmount = $util.Long.fromValue(object.aliceAmount)).unsigned = true;
                else if (typeof object.aliceAmount === "string")
                    message.aliceAmount = parseInt(object.aliceAmount, 10);
                else if (typeof object.aliceAmount === "number")
                    message.aliceAmount = object.aliceAmount;
                else if (typeof object.aliceAmount === "object")
                    message.aliceAmount = new $util.LongBits(object.aliceAmount.low >>> 0, object.aliceAmount.high >>> 0).toNumber(true);
            if (object.alicePubkey != null)
                if (typeof object.alicePubkey === "string")
                    $util.base64.decode(object.alicePubkey, message.alicePubkey = $util.newBuffer($util.base64.length(object.alicePubkey)), 0);
                else if (object.alicePubkey.length >= 0)
                    message.alicePubkey = object.alicePubkey;
            if (object.aliceCommitment != null)
                if (typeof object.aliceCommitment === "string")
                    $util.base64.decode(object.aliceCommitment, message.aliceCommitment = $util.newBuffer($util.base64.length(object.aliceCommitment)), 0);
                else if (object.aliceCommitment.length >= 0)
                    message.aliceCommitment = object.aliceCommitment;
            if (object.aliceAdaptorSig != null) {
                if (typeof object.aliceAdaptorSig !== "object")
                    throw TypeError(".p2p.AtomicSwap.aliceAdaptorSig: object expected");
                message.aliceAdaptorSig = $root.p2p.AdaptorSignature.fromObject(object.aliceAdaptorSig);
            }
            if (object.aliceTimeoutHeight != null)
                if ($util.Long)
                    (message.aliceTimeoutHeight = $util.Long.fromValue(object.aliceTimeoutHeight)).unsigned = true;
                else if (typeof object.aliceTimeoutHeight === "string")
                    message.aliceTimeoutHeight = parseInt(object.aliceTimeoutHeight, 10);
                else if (typeof object.aliceTimeoutHeight === "number")
                    message.aliceTimeoutHeight = object.aliceTimeoutHeight;
                else if (typeof object.aliceTimeoutHeight === "object")
                    message.aliceTimeoutHeight = new $util.LongBits(object.aliceTimeoutHeight.low >>> 0, object.aliceTimeoutHeight.high >>> 0).toNumber(true);
            if (object.bobAmount != null)
                if ($util.Long)
                    (message.bobAmount = $util.Long.fromValue(object.bobAmount)).unsigned = true;
                else if (typeof object.bobAmount === "string")
                    message.bobAmount = parseInt(object.bobAmount, 10);
                else if (typeof object.bobAmount === "number")
                    message.bobAmount = object.bobAmount;
                else if (typeof object.bobAmount === "object")
                    message.bobAmount = new $util.LongBits(object.bobAmount.low >>> 0, object.bobAmount.high >>> 0).toNumber(true);
            if (object.bobPubkey != null)
                if (typeof object.bobPubkey === "string")
                    $util.base64.decode(object.bobPubkey, message.bobPubkey = $util.newBuffer($util.base64.length(object.bobPubkey)), 0);
                else if (object.bobPubkey.length >= 0)
                    message.bobPubkey = object.bobPubkey;
            if (object.bobBtcAddress != null)
                message.bobBtcAddress = String(object.bobBtcAddress);
            if (object.bobBtcTxid != null)
                message.bobBtcTxid = String(object.bobBtcTxid);
            if (object.bobBtcVout != null)
                message.bobBtcVout = object.bobBtcVout >>> 0;
            if (object.bobAdaptorSig != null)
                if (typeof object.bobAdaptorSig === "string")
                    $util.base64.decode(object.bobAdaptorSig, message.bobAdaptorSig = $util.newBuffer($util.base64.length(object.bobAdaptorSig)), 0);
                else if (object.bobAdaptorSig.length >= 0)
                    message.bobAdaptorSig = object.bobAdaptorSig;
            if (object.bobTimeoutHeight != null)
                if ($util.Long)
                    (message.bobTimeoutHeight = $util.Long.fromValue(object.bobTimeoutHeight)).unsigned = true;
                else if (typeof object.bobTimeoutHeight === "string")
                    message.bobTimeoutHeight = parseInt(object.bobTimeoutHeight, 10);
                else if (typeof object.bobTimeoutHeight === "number")
                    message.bobTimeoutHeight = object.bobTimeoutHeight;
                else if (typeof object.bobTimeoutHeight === "object")
                    message.bobTimeoutHeight = new $util.LongBits(object.bobTimeoutHeight.low >>> 0, object.bobTimeoutHeight.high >>> 0).toNumber(true);
            if (object.sharedAdaptorPoint != null)
                if (typeof object.sharedAdaptorPoint === "string")
                    $util.base64.decode(object.sharedAdaptorPoint, message.sharedAdaptorPoint = $util.newBuffer($util.base64.length(object.sharedAdaptorPoint)), 0);
                else if (object.sharedAdaptorPoint.length >= 0)
                    message.sharedAdaptorPoint = object.sharedAdaptorPoint;
            if (object.secretHash != null)
                if (typeof object.secretHash === "string")
                    $util.base64.decode(object.secretHash, message.secretHash = $util.newBuffer($util.base64.length(object.secretHash)), 0);
                else if (object.secretHash.length >= 0)
                    message.secretHash = object.secretHash;
            if (object.createdAt != null)
                if ($util.Long)
                    (message.createdAt = $util.Long.fromValue(object.createdAt)).unsigned = true;
                else if (typeof object.createdAt === "string")
                    message.createdAt = parseInt(object.createdAt, 10);
                else if (typeof object.createdAt === "number")
                    message.createdAt = object.createdAt;
                else if (typeof object.createdAt === "object")
                    message.createdAt = new $util.LongBits(object.createdAt.low >>> 0, object.createdAt.high >>> 0).toNumber(true);
            if (object.expiresAt != null)
                if ($util.Long)
                    (message.expiresAt = $util.Long.fromValue(object.expiresAt)).unsigned = true;
                else if (typeof object.expiresAt === "string")
                    message.expiresAt = parseInt(object.expiresAt, 10);
                else if (typeof object.expiresAt === "number")
                    message.expiresAt = object.expiresAt;
                else if (typeof object.expiresAt === "object")
                    message.expiresAt = new $util.LongBits(object.expiresAt.low >>> 0, object.expiresAt.high >>> 0).toNumber(true);
            if (object.lastUpdated != null)
                if ($util.Long)
                    (message.lastUpdated = $util.Long.fromValue(object.lastUpdated)).unsigned = true;
                else if (typeof object.lastUpdated === "string")
                    message.lastUpdated = parseInt(object.lastUpdated, 10);
                else if (typeof object.lastUpdated === "number")
                    message.lastUpdated = object.lastUpdated;
                else if (typeof object.lastUpdated === "object")
                    message.lastUpdated = new $util.LongBits(object.lastUpdated.low >>> 0, object.lastUpdated.high >>> 0).toNumber(true);
            return message;
        };

        /**
         * Creates a plain object from an AtomicSwap message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.AtomicSwap
         * @static
         * @param {p2p.AtomicSwap} message AtomicSwap
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        AtomicSwap.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.swapId = "";
                else {
                    object.swapId = [];
                    if (options.bytes !== Array)
                        object.swapId = $util.newBuffer(object.swapId);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.stateEnum = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.stateEnum = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.aliceAmount = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.aliceAmount = options.longs === String ? "0" : 0;
                if (options.bytes === String)
                    object.alicePubkey = "";
                else {
                    object.alicePubkey = [];
                    if (options.bytes !== Array)
                        object.alicePubkey = $util.newBuffer(object.alicePubkey);
                }
                if (options.bytes === String)
                    object.aliceCommitment = "";
                else {
                    object.aliceCommitment = [];
                    if (options.bytes !== Array)
                        object.aliceCommitment = $util.newBuffer(object.aliceCommitment);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.aliceTimeoutHeight = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.aliceTimeoutHeight = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.bobAmount = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.bobAmount = options.longs === String ? "0" : 0;
                if (options.bytes === String)
                    object.bobPubkey = "";
                else {
                    object.bobPubkey = [];
                    if (options.bytes !== Array)
                        object.bobPubkey = $util.newBuffer(object.bobPubkey);
                }
                object.bobBtcAddress = "";
                object.bobBtcTxid = "";
                object.bobBtcVout = 0;
                if (options.bytes === String)
                    object.bobAdaptorSig = "";
                else {
                    object.bobAdaptorSig = [];
                    if (options.bytes !== Array)
                        object.bobAdaptorSig = $util.newBuffer(object.bobAdaptorSig);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.bobTimeoutHeight = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.bobTimeoutHeight = options.longs === String ? "0" : 0;
                if (options.bytes === String)
                    object.sharedAdaptorPoint = "";
                else {
                    object.sharedAdaptorPoint = [];
                    if (options.bytes !== Array)
                        object.sharedAdaptorPoint = $util.newBuffer(object.sharedAdaptorPoint);
                }
                if (options.bytes === String)
                    object.secretHash = "";
                else {
                    object.secretHash = [];
                    if (options.bytes !== Array)
                        object.secretHash = $util.newBuffer(object.secretHash);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.createdAt = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.createdAt = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.expiresAt = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.expiresAt = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.lastUpdated = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.lastUpdated = options.longs === String ? "0" : 0;
            }
            if (message.swapId != null && message.hasOwnProperty("swapId"))
                object.swapId = options.bytes === String ? $util.base64.encode(message.swapId, 0, message.swapId.length) : options.bytes === Array ? Array.prototype.slice.call(message.swapId) : message.swapId;
            if (message.stateEnum != null && message.hasOwnProperty("stateEnum"))
                if (typeof message.stateEnum === "number")
                    object.stateEnum = options.longs === String ? String(message.stateEnum) : message.stateEnum;
                else
                    object.stateEnum = options.longs === String ? $util.Long.prototype.toString.call(message.stateEnum) : options.longs === Number ? new $util.LongBits(message.stateEnum.low >>> 0, message.stateEnum.high >>> 0).toNumber(true) : message.stateEnum;
            if (message.aliceAmount != null && message.hasOwnProperty("aliceAmount"))
                if (typeof message.aliceAmount === "number")
                    object.aliceAmount = options.longs === String ? String(message.aliceAmount) : message.aliceAmount;
                else
                    object.aliceAmount = options.longs === String ? $util.Long.prototype.toString.call(message.aliceAmount) : options.longs === Number ? new $util.LongBits(message.aliceAmount.low >>> 0, message.aliceAmount.high >>> 0).toNumber(true) : message.aliceAmount;
            if (message.alicePubkey != null && message.hasOwnProperty("alicePubkey"))
                object.alicePubkey = options.bytes === String ? $util.base64.encode(message.alicePubkey, 0, message.alicePubkey.length) : options.bytes === Array ? Array.prototype.slice.call(message.alicePubkey) : message.alicePubkey;
            if (message.aliceCommitment != null && message.hasOwnProperty("aliceCommitment"))
                object.aliceCommitment = options.bytes === String ? $util.base64.encode(message.aliceCommitment, 0, message.aliceCommitment.length) : options.bytes === Array ? Array.prototype.slice.call(message.aliceCommitment) : message.aliceCommitment;
            if (message.aliceAdaptorSig != null && message.hasOwnProperty("aliceAdaptorSig")) {
                object.aliceAdaptorSig = $root.p2p.AdaptorSignature.toObject(message.aliceAdaptorSig, options);
                if (options.oneofs)
                    object._aliceAdaptorSig = "aliceAdaptorSig";
            }
            if (message.aliceTimeoutHeight != null && message.hasOwnProperty("aliceTimeoutHeight"))
                if (typeof message.aliceTimeoutHeight === "number")
                    object.aliceTimeoutHeight = options.longs === String ? String(message.aliceTimeoutHeight) : message.aliceTimeoutHeight;
                else
                    object.aliceTimeoutHeight = options.longs === String ? $util.Long.prototype.toString.call(message.aliceTimeoutHeight) : options.longs === Number ? new $util.LongBits(message.aliceTimeoutHeight.low >>> 0, message.aliceTimeoutHeight.high >>> 0).toNumber(true) : message.aliceTimeoutHeight;
            if (message.bobAmount != null && message.hasOwnProperty("bobAmount"))
                if (typeof message.bobAmount === "number")
                    object.bobAmount = options.longs === String ? String(message.bobAmount) : message.bobAmount;
                else
                    object.bobAmount = options.longs === String ? $util.Long.prototype.toString.call(message.bobAmount) : options.longs === Number ? new $util.LongBits(message.bobAmount.low >>> 0, message.bobAmount.high >>> 0).toNumber(true) : message.bobAmount;
            if (message.bobPubkey != null && message.hasOwnProperty("bobPubkey"))
                object.bobPubkey = options.bytes === String ? $util.base64.encode(message.bobPubkey, 0, message.bobPubkey.length) : options.bytes === Array ? Array.prototype.slice.call(message.bobPubkey) : message.bobPubkey;
            if (message.bobBtcAddress != null && message.hasOwnProperty("bobBtcAddress"))
                object.bobBtcAddress = message.bobBtcAddress;
            if (message.bobBtcTxid != null && message.hasOwnProperty("bobBtcTxid"))
                object.bobBtcTxid = message.bobBtcTxid;
            if (message.bobBtcVout != null && message.hasOwnProperty("bobBtcVout"))
                object.bobBtcVout = message.bobBtcVout;
            if (message.bobAdaptorSig != null && message.hasOwnProperty("bobAdaptorSig"))
                object.bobAdaptorSig = options.bytes === String ? $util.base64.encode(message.bobAdaptorSig, 0, message.bobAdaptorSig.length) : options.bytes === Array ? Array.prototype.slice.call(message.bobAdaptorSig) : message.bobAdaptorSig;
            if (message.bobTimeoutHeight != null && message.hasOwnProperty("bobTimeoutHeight"))
                if (typeof message.bobTimeoutHeight === "number")
                    object.bobTimeoutHeight = options.longs === String ? String(message.bobTimeoutHeight) : message.bobTimeoutHeight;
                else
                    object.bobTimeoutHeight = options.longs === String ? $util.Long.prototype.toString.call(message.bobTimeoutHeight) : options.longs === Number ? new $util.LongBits(message.bobTimeoutHeight.low >>> 0, message.bobTimeoutHeight.high >>> 0).toNumber(true) : message.bobTimeoutHeight;
            if (message.sharedAdaptorPoint != null && message.hasOwnProperty("sharedAdaptorPoint"))
                object.sharedAdaptorPoint = options.bytes === String ? $util.base64.encode(message.sharedAdaptorPoint, 0, message.sharedAdaptorPoint.length) : options.bytes === Array ? Array.prototype.slice.call(message.sharedAdaptorPoint) : message.sharedAdaptorPoint;
            if (message.secretHash != null && message.hasOwnProperty("secretHash"))
                object.secretHash = options.bytes === String ? $util.base64.encode(message.secretHash, 0, message.secretHash.length) : options.bytes === Array ? Array.prototype.slice.call(message.secretHash) : message.secretHash;
            if (message.createdAt != null && message.hasOwnProperty("createdAt"))
                if (typeof message.createdAt === "number")
                    object.createdAt = options.longs === String ? String(message.createdAt) : message.createdAt;
                else
                    object.createdAt = options.longs === String ? $util.Long.prototype.toString.call(message.createdAt) : options.longs === Number ? new $util.LongBits(message.createdAt.low >>> 0, message.createdAt.high >>> 0).toNumber(true) : message.createdAt;
            if (message.expiresAt != null && message.hasOwnProperty("expiresAt"))
                if (typeof message.expiresAt === "number")
                    object.expiresAt = options.longs === String ? String(message.expiresAt) : message.expiresAt;
                else
                    object.expiresAt = options.longs === String ? $util.Long.prototype.toString.call(message.expiresAt) : options.longs === Number ? new $util.LongBits(message.expiresAt.low >>> 0, message.expiresAt.high >>> 0).toNumber(true) : message.expiresAt;
            if (message.lastUpdated != null && message.hasOwnProperty("lastUpdated"))
                if (typeof message.lastUpdated === "number")
                    object.lastUpdated = options.longs === String ? String(message.lastUpdated) : message.lastUpdated;
                else
                    object.lastUpdated = options.longs === String ? $util.Long.prototype.toString.call(message.lastUpdated) : options.longs === Number ? new $util.LongBits(message.lastUpdated.low >>> 0, message.lastUpdated.high >>> 0).toNumber(true) : message.lastUpdated;
            return object;
        };

        /**
         * Converts this AtomicSwap to JSON.
         * @function toJSON
         * @memberof p2p.AtomicSwap
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        AtomicSwap.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for AtomicSwap
         * @function getTypeUrl
         * @memberof p2p.AtomicSwap
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        AtomicSwap.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.AtomicSwap";
        };

        return AtomicSwap;
    })();

    p2p.SwapAliceAdaptorSig = (function() {

        /**
         * Properties of a SwapAliceAdaptorSig.
         * @memberof p2p
         * @interface ISwapAliceAdaptorSig
         * @property {Uint8Array|null} [swapId] SwapAliceAdaptorSig swapId
         * @property {p2p.IAdaptorSignature|null} [adaptorSig] SwapAliceAdaptorSig adaptorSig
         */

        /**
         * Constructs a new SwapAliceAdaptorSig.
         * @memberof p2p
         * @classdesc Represents a SwapAliceAdaptorSig.
         * @implements ISwapAliceAdaptorSig
         * @constructor
         * @param {p2p.ISwapAliceAdaptorSig=} [properties] Properties to set
         */
        function SwapAliceAdaptorSig(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * SwapAliceAdaptorSig swapId.
         * @member {Uint8Array} swapId
         * @memberof p2p.SwapAliceAdaptorSig
         * @instance
         */
        SwapAliceAdaptorSig.prototype.swapId = $util.newBuffer([]);

        /**
         * SwapAliceAdaptorSig adaptorSig.
         * @member {p2p.IAdaptorSignature|null|undefined} adaptorSig
         * @memberof p2p.SwapAliceAdaptorSig
         * @instance
         */
        SwapAliceAdaptorSig.prototype.adaptorSig = null;

        /**
         * Creates a new SwapAliceAdaptorSig instance using the specified properties.
         * @function create
         * @memberof p2p.SwapAliceAdaptorSig
         * @static
         * @param {p2p.ISwapAliceAdaptorSig=} [properties] Properties to set
         * @returns {p2p.SwapAliceAdaptorSig} SwapAliceAdaptorSig instance
         */
        SwapAliceAdaptorSig.create = function create(properties) {
            return new SwapAliceAdaptorSig(properties);
        };

        /**
         * Encodes the specified SwapAliceAdaptorSig message. Does not implicitly {@link p2p.SwapAliceAdaptorSig.verify|verify} messages.
         * @function encode
         * @memberof p2p.SwapAliceAdaptorSig
         * @static
         * @param {p2p.ISwapAliceAdaptorSig} message SwapAliceAdaptorSig message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        SwapAliceAdaptorSig.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.swapId != null && Object.hasOwnProperty.call(message, "swapId"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.swapId);
            if (message.adaptorSig != null && Object.hasOwnProperty.call(message, "adaptorSig"))
                $root.p2p.AdaptorSignature.encode(message.adaptorSig, writer.uint32(/* id 2, wireType 2 =*/18).fork()).ldelim();
            return writer;
        };

        /**
         * Encodes the specified SwapAliceAdaptorSig message, length delimited. Does not implicitly {@link p2p.SwapAliceAdaptorSig.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.SwapAliceAdaptorSig
         * @static
         * @param {p2p.ISwapAliceAdaptorSig} message SwapAliceAdaptorSig message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        SwapAliceAdaptorSig.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a SwapAliceAdaptorSig message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.SwapAliceAdaptorSig
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.SwapAliceAdaptorSig} SwapAliceAdaptorSig
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        SwapAliceAdaptorSig.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.SwapAliceAdaptorSig();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.swapId = reader.bytes();
                        break;
                    }
                case 2: {
                        message.adaptorSig = $root.p2p.AdaptorSignature.decode(reader, reader.uint32());
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a SwapAliceAdaptorSig message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.SwapAliceAdaptorSig
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.SwapAliceAdaptorSig} SwapAliceAdaptorSig
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        SwapAliceAdaptorSig.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a SwapAliceAdaptorSig message.
         * @function verify
         * @memberof p2p.SwapAliceAdaptorSig
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        SwapAliceAdaptorSig.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.swapId != null && message.hasOwnProperty("swapId"))
                if (!(message.swapId && typeof message.swapId.length === "number" || $util.isString(message.swapId)))
                    return "swapId: buffer expected";
            if (message.adaptorSig != null && message.hasOwnProperty("adaptorSig")) {
                var error = $root.p2p.AdaptorSignature.verify(message.adaptorSig);
                if (error)
                    return "adaptorSig." + error;
            }
            return null;
        };

        /**
         * Creates a SwapAliceAdaptorSig message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.SwapAliceAdaptorSig
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.SwapAliceAdaptorSig} SwapAliceAdaptorSig
         */
        SwapAliceAdaptorSig.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.SwapAliceAdaptorSig)
                return object;
            var message = new $root.p2p.SwapAliceAdaptorSig();
            if (object.swapId != null)
                if (typeof object.swapId === "string")
                    $util.base64.decode(object.swapId, message.swapId = $util.newBuffer($util.base64.length(object.swapId)), 0);
                else if (object.swapId.length >= 0)
                    message.swapId = object.swapId;
            if (object.adaptorSig != null) {
                if (typeof object.adaptorSig !== "object")
                    throw TypeError(".p2p.SwapAliceAdaptorSig.adaptorSig: object expected");
                message.adaptorSig = $root.p2p.AdaptorSignature.fromObject(object.adaptorSig);
            }
            return message;
        };

        /**
         * Creates a plain object from a SwapAliceAdaptorSig message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.SwapAliceAdaptorSig
         * @static
         * @param {p2p.SwapAliceAdaptorSig} message SwapAliceAdaptorSig
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        SwapAliceAdaptorSig.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.swapId = "";
                else {
                    object.swapId = [];
                    if (options.bytes !== Array)
                        object.swapId = $util.newBuffer(object.swapId);
                }
                object.adaptorSig = null;
            }
            if (message.swapId != null && message.hasOwnProperty("swapId"))
                object.swapId = options.bytes === String ? $util.base64.encode(message.swapId, 0, message.swapId.length) : options.bytes === Array ? Array.prototype.slice.call(message.swapId) : message.swapId;
            if (message.adaptorSig != null && message.hasOwnProperty("adaptorSig"))
                object.adaptorSig = $root.p2p.AdaptorSignature.toObject(message.adaptorSig, options);
            return object;
        };

        /**
         * Converts this SwapAliceAdaptorSig to JSON.
         * @function toJSON
         * @memberof p2p.SwapAliceAdaptorSig
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        SwapAliceAdaptorSig.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for SwapAliceAdaptorSig
         * @function getTypeUrl
         * @memberof p2p.SwapAliceAdaptorSig
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        SwapAliceAdaptorSig.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.SwapAliceAdaptorSig";
        };

        return SwapAliceAdaptorSig;
    })();

    p2p.ChannelProposal = (function() {

        /**
         * Properties of a ChannelProposal.
         * @memberof p2p
         * @interface IChannelProposal
         * @property {Uint8Array|null} [channelId] ChannelProposal channelId
         * @property {number|null} [version] ChannelProposal version
         * @property {Uint8Array|null} [partyAPubkey] ChannelProposal partyAPubkey
         * @property {number|Long|null} [partyAFunding] ChannelProposal partyAFunding
         * @property {Uint8Array|null} [partyBPubkey] ChannelProposal partyBPubkey
         * @property {number|Long|null} [partyBFunding] ChannelProposal partyBFunding
         * @property {number|Long|null} [disputePeriod] ChannelProposal disputePeriod
         * @property {number|Long|null} [minConfirmations] ChannelProposal minConfirmations
         * @property {number|Long|null} [createdAt] ChannelProposal createdAt
         */

        /**
         * Constructs a new ChannelProposal.
         * @memberof p2p
         * @classdesc Represents a ChannelProposal.
         * @implements IChannelProposal
         * @constructor
         * @param {p2p.IChannelProposal=} [properties] Properties to set
         */
        function ChannelProposal(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * ChannelProposal channelId.
         * @member {Uint8Array} channelId
         * @memberof p2p.ChannelProposal
         * @instance
         */
        ChannelProposal.prototype.channelId = $util.newBuffer([]);

        /**
         * ChannelProposal version.
         * @member {number} version
         * @memberof p2p.ChannelProposal
         * @instance
         */
        ChannelProposal.prototype.version = 0;

        /**
         * ChannelProposal partyAPubkey.
         * @member {Uint8Array} partyAPubkey
         * @memberof p2p.ChannelProposal
         * @instance
         */
        ChannelProposal.prototype.partyAPubkey = $util.newBuffer([]);

        /**
         * ChannelProposal partyAFunding.
         * @member {number|Long} partyAFunding
         * @memberof p2p.ChannelProposal
         * @instance
         */
        ChannelProposal.prototype.partyAFunding = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * ChannelProposal partyBPubkey.
         * @member {Uint8Array} partyBPubkey
         * @memberof p2p.ChannelProposal
         * @instance
         */
        ChannelProposal.prototype.partyBPubkey = $util.newBuffer([]);

        /**
         * ChannelProposal partyBFunding.
         * @member {number|Long} partyBFunding
         * @memberof p2p.ChannelProposal
         * @instance
         */
        ChannelProposal.prototype.partyBFunding = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * ChannelProposal disputePeriod.
         * @member {number|Long} disputePeriod
         * @memberof p2p.ChannelProposal
         * @instance
         */
        ChannelProposal.prototype.disputePeriod = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * ChannelProposal minConfirmations.
         * @member {number|Long} minConfirmations
         * @memberof p2p.ChannelProposal
         * @instance
         */
        ChannelProposal.prototype.minConfirmations = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * ChannelProposal createdAt.
         * @member {number|Long} createdAt
         * @memberof p2p.ChannelProposal
         * @instance
         */
        ChannelProposal.prototype.createdAt = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Creates a new ChannelProposal instance using the specified properties.
         * @function create
         * @memberof p2p.ChannelProposal
         * @static
         * @param {p2p.IChannelProposal=} [properties] Properties to set
         * @returns {p2p.ChannelProposal} ChannelProposal instance
         */
        ChannelProposal.create = function create(properties) {
            return new ChannelProposal(properties);
        };

        /**
         * Encodes the specified ChannelProposal message. Does not implicitly {@link p2p.ChannelProposal.verify|verify} messages.
         * @function encode
         * @memberof p2p.ChannelProposal
         * @static
         * @param {p2p.IChannelProposal} message ChannelProposal message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        ChannelProposal.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.channelId != null && Object.hasOwnProperty.call(message, "channelId"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.channelId);
            if (message.version != null && Object.hasOwnProperty.call(message, "version"))
                writer.uint32(/* id 2, wireType 0 =*/16).uint32(message.version);
            if (message.partyAPubkey != null && Object.hasOwnProperty.call(message, "partyAPubkey"))
                writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.partyAPubkey);
            if (message.partyAFunding != null && Object.hasOwnProperty.call(message, "partyAFunding"))
                writer.uint32(/* id 4, wireType 0 =*/32).uint64(message.partyAFunding);
            if (message.partyBPubkey != null && Object.hasOwnProperty.call(message, "partyBPubkey"))
                writer.uint32(/* id 5, wireType 2 =*/42).bytes(message.partyBPubkey);
            if (message.partyBFunding != null && Object.hasOwnProperty.call(message, "partyBFunding"))
                writer.uint32(/* id 6, wireType 0 =*/48).uint64(message.partyBFunding);
            if (message.disputePeriod != null && Object.hasOwnProperty.call(message, "disputePeriod"))
                writer.uint32(/* id 7, wireType 0 =*/56).uint64(message.disputePeriod);
            if (message.minConfirmations != null && Object.hasOwnProperty.call(message, "minConfirmations"))
                writer.uint32(/* id 8, wireType 0 =*/64).uint64(message.minConfirmations);
            if (message.createdAt != null && Object.hasOwnProperty.call(message, "createdAt"))
                writer.uint32(/* id 9, wireType 0 =*/72).uint64(message.createdAt);
            return writer;
        };

        /**
         * Encodes the specified ChannelProposal message, length delimited. Does not implicitly {@link p2p.ChannelProposal.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.ChannelProposal
         * @static
         * @param {p2p.IChannelProposal} message ChannelProposal message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        ChannelProposal.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a ChannelProposal message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.ChannelProposal
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.ChannelProposal} ChannelProposal
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        ChannelProposal.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.ChannelProposal();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.channelId = reader.bytes();
                        break;
                    }
                case 2: {
                        message.version = reader.uint32();
                        break;
                    }
                case 3: {
                        message.partyAPubkey = reader.bytes();
                        break;
                    }
                case 4: {
                        message.partyAFunding = reader.uint64();
                        break;
                    }
                case 5: {
                        message.partyBPubkey = reader.bytes();
                        break;
                    }
                case 6: {
                        message.partyBFunding = reader.uint64();
                        break;
                    }
                case 7: {
                        message.disputePeriod = reader.uint64();
                        break;
                    }
                case 8: {
                        message.minConfirmations = reader.uint64();
                        break;
                    }
                case 9: {
                        message.createdAt = reader.uint64();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a ChannelProposal message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.ChannelProposal
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.ChannelProposal} ChannelProposal
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        ChannelProposal.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a ChannelProposal message.
         * @function verify
         * @memberof p2p.ChannelProposal
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        ChannelProposal.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.channelId != null && message.hasOwnProperty("channelId"))
                if (!(message.channelId && typeof message.channelId.length === "number" || $util.isString(message.channelId)))
                    return "channelId: buffer expected";
            if (message.version != null && message.hasOwnProperty("version"))
                if (!$util.isInteger(message.version))
                    return "version: integer expected";
            if (message.partyAPubkey != null && message.hasOwnProperty("partyAPubkey"))
                if (!(message.partyAPubkey && typeof message.partyAPubkey.length === "number" || $util.isString(message.partyAPubkey)))
                    return "partyAPubkey: buffer expected";
            if (message.partyAFunding != null && message.hasOwnProperty("partyAFunding"))
                if (!$util.isInteger(message.partyAFunding) && !(message.partyAFunding && $util.isInteger(message.partyAFunding.low) && $util.isInteger(message.partyAFunding.high)))
                    return "partyAFunding: integer|Long expected";
            if (message.partyBPubkey != null && message.hasOwnProperty("partyBPubkey"))
                if (!(message.partyBPubkey && typeof message.partyBPubkey.length === "number" || $util.isString(message.partyBPubkey)))
                    return "partyBPubkey: buffer expected";
            if (message.partyBFunding != null && message.hasOwnProperty("partyBFunding"))
                if (!$util.isInteger(message.partyBFunding) && !(message.partyBFunding && $util.isInteger(message.partyBFunding.low) && $util.isInteger(message.partyBFunding.high)))
                    return "partyBFunding: integer|Long expected";
            if (message.disputePeriod != null && message.hasOwnProperty("disputePeriod"))
                if (!$util.isInteger(message.disputePeriod) && !(message.disputePeriod && $util.isInteger(message.disputePeriod.low) && $util.isInteger(message.disputePeriod.high)))
                    return "disputePeriod: integer|Long expected";
            if (message.minConfirmations != null && message.hasOwnProperty("minConfirmations"))
                if (!$util.isInteger(message.minConfirmations) && !(message.minConfirmations && $util.isInteger(message.minConfirmations.low) && $util.isInteger(message.minConfirmations.high)))
                    return "minConfirmations: integer|Long expected";
            if (message.createdAt != null && message.hasOwnProperty("createdAt"))
                if (!$util.isInteger(message.createdAt) && !(message.createdAt && $util.isInteger(message.createdAt.low) && $util.isInteger(message.createdAt.high)))
                    return "createdAt: integer|Long expected";
            return null;
        };

        /**
         * Creates a ChannelProposal message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.ChannelProposal
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.ChannelProposal} ChannelProposal
         */
        ChannelProposal.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.ChannelProposal)
                return object;
            var message = new $root.p2p.ChannelProposal();
            if (object.channelId != null)
                if (typeof object.channelId === "string")
                    $util.base64.decode(object.channelId, message.channelId = $util.newBuffer($util.base64.length(object.channelId)), 0);
                else if (object.channelId.length >= 0)
                    message.channelId = object.channelId;
            if (object.version != null)
                message.version = object.version >>> 0;
            if (object.partyAPubkey != null)
                if (typeof object.partyAPubkey === "string")
                    $util.base64.decode(object.partyAPubkey, message.partyAPubkey = $util.newBuffer($util.base64.length(object.partyAPubkey)), 0);
                else if (object.partyAPubkey.length >= 0)
                    message.partyAPubkey = object.partyAPubkey;
            if (object.partyAFunding != null)
                if ($util.Long)
                    (message.partyAFunding = $util.Long.fromValue(object.partyAFunding)).unsigned = true;
                else if (typeof object.partyAFunding === "string")
                    message.partyAFunding = parseInt(object.partyAFunding, 10);
                else if (typeof object.partyAFunding === "number")
                    message.partyAFunding = object.partyAFunding;
                else if (typeof object.partyAFunding === "object")
                    message.partyAFunding = new $util.LongBits(object.partyAFunding.low >>> 0, object.partyAFunding.high >>> 0).toNumber(true);
            if (object.partyBPubkey != null)
                if (typeof object.partyBPubkey === "string")
                    $util.base64.decode(object.partyBPubkey, message.partyBPubkey = $util.newBuffer($util.base64.length(object.partyBPubkey)), 0);
                else if (object.partyBPubkey.length >= 0)
                    message.partyBPubkey = object.partyBPubkey;
            if (object.partyBFunding != null)
                if ($util.Long)
                    (message.partyBFunding = $util.Long.fromValue(object.partyBFunding)).unsigned = true;
                else if (typeof object.partyBFunding === "string")
                    message.partyBFunding = parseInt(object.partyBFunding, 10);
                else if (typeof object.partyBFunding === "number")
                    message.partyBFunding = object.partyBFunding;
                else if (typeof object.partyBFunding === "object")
                    message.partyBFunding = new $util.LongBits(object.partyBFunding.low >>> 0, object.partyBFunding.high >>> 0).toNumber(true);
            if (object.disputePeriod != null)
                if ($util.Long)
                    (message.disputePeriod = $util.Long.fromValue(object.disputePeriod)).unsigned = true;
                else if (typeof object.disputePeriod === "string")
                    message.disputePeriod = parseInt(object.disputePeriod, 10);
                else if (typeof object.disputePeriod === "number")
                    message.disputePeriod = object.disputePeriod;
                else if (typeof object.disputePeriod === "object")
                    message.disputePeriod = new $util.LongBits(object.disputePeriod.low >>> 0, object.disputePeriod.high >>> 0).toNumber(true);
            if (object.minConfirmations != null)
                if ($util.Long)
                    (message.minConfirmations = $util.Long.fromValue(object.minConfirmations)).unsigned = true;
                else if (typeof object.minConfirmations === "string")
                    message.minConfirmations = parseInt(object.minConfirmations, 10);
                else if (typeof object.minConfirmations === "number")
                    message.minConfirmations = object.minConfirmations;
                else if (typeof object.minConfirmations === "object")
                    message.minConfirmations = new $util.LongBits(object.minConfirmations.low >>> 0, object.minConfirmations.high >>> 0).toNumber(true);
            if (object.createdAt != null)
                if ($util.Long)
                    (message.createdAt = $util.Long.fromValue(object.createdAt)).unsigned = true;
                else if (typeof object.createdAt === "string")
                    message.createdAt = parseInt(object.createdAt, 10);
                else if (typeof object.createdAt === "number")
                    message.createdAt = object.createdAt;
                else if (typeof object.createdAt === "object")
                    message.createdAt = new $util.LongBits(object.createdAt.low >>> 0, object.createdAt.high >>> 0).toNumber(true);
            return message;
        };

        /**
         * Creates a plain object from a ChannelProposal message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.ChannelProposal
         * @static
         * @param {p2p.ChannelProposal} message ChannelProposal
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        ChannelProposal.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.channelId = "";
                else {
                    object.channelId = [];
                    if (options.bytes !== Array)
                        object.channelId = $util.newBuffer(object.channelId);
                }
                object.version = 0;
                if (options.bytes === String)
                    object.partyAPubkey = "";
                else {
                    object.partyAPubkey = [];
                    if (options.bytes !== Array)
                        object.partyAPubkey = $util.newBuffer(object.partyAPubkey);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.partyAFunding = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.partyAFunding = options.longs === String ? "0" : 0;
                if (options.bytes === String)
                    object.partyBPubkey = "";
                else {
                    object.partyBPubkey = [];
                    if (options.bytes !== Array)
                        object.partyBPubkey = $util.newBuffer(object.partyBPubkey);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.partyBFunding = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.partyBFunding = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.disputePeriod = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.disputePeriod = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.minConfirmations = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.minConfirmations = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.createdAt = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.createdAt = options.longs === String ? "0" : 0;
            }
            if (message.channelId != null && message.hasOwnProperty("channelId"))
                object.channelId = options.bytes === String ? $util.base64.encode(message.channelId, 0, message.channelId.length) : options.bytes === Array ? Array.prototype.slice.call(message.channelId) : message.channelId;
            if (message.version != null && message.hasOwnProperty("version"))
                object.version = message.version;
            if (message.partyAPubkey != null && message.hasOwnProperty("partyAPubkey"))
                object.partyAPubkey = options.bytes === String ? $util.base64.encode(message.partyAPubkey, 0, message.partyAPubkey.length) : options.bytes === Array ? Array.prototype.slice.call(message.partyAPubkey) : message.partyAPubkey;
            if (message.partyAFunding != null && message.hasOwnProperty("partyAFunding"))
                if (typeof message.partyAFunding === "number")
                    object.partyAFunding = options.longs === String ? String(message.partyAFunding) : message.partyAFunding;
                else
                    object.partyAFunding = options.longs === String ? $util.Long.prototype.toString.call(message.partyAFunding) : options.longs === Number ? new $util.LongBits(message.partyAFunding.low >>> 0, message.partyAFunding.high >>> 0).toNumber(true) : message.partyAFunding;
            if (message.partyBPubkey != null && message.hasOwnProperty("partyBPubkey"))
                object.partyBPubkey = options.bytes === String ? $util.base64.encode(message.partyBPubkey, 0, message.partyBPubkey.length) : options.bytes === Array ? Array.prototype.slice.call(message.partyBPubkey) : message.partyBPubkey;
            if (message.partyBFunding != null && message.hasOwnProperty("partyBFunding"))
                if (typeof message.partyBFunding === "number")
                    object.partyBFunding = options.longs === String ? String(message.partyBFunding) : message.partyBFunding;
                else
                    object.partyBFunding = options.longs === String ? $util.Long.prototype.toString.call(message.partyBFunding) : options.longs === Number ? new $util.LongBits(message.partyBFunding.low >>> 0, message.partyBFunding.high >>> 0).toNumber(true) : message.partyBFunding;
            if (message.disputePeriod != null && message.hasOwnProperty("disputePeriod"))
                if (typeof message.disputePeriod === "number")
                    object.disputePeriod = options.longs === String ? String(message.disputePeriod) : message.disputePeriod;
                else
                    object.disputePeriod = options.longs === String ? $util.Long.prototype.toString.call(message.disputePeriod) : options.longs === Number ? new $util.LongBits(message.disputePeriod.low >>> 0, message.disputePeriod.high >>> 0).toNumber(true) : message.disputePeriod;
            if (message.minConfirmations != null && message.hasOwnProperty("minConfirmations"))
                if (typeof message.minConfirmations === "number")
                    object.minConfirmations = options.longs === String ? String(message.minConfirmations) : message.minConfirmations;
                else
                    object.minConfirmations = options.longs === String ? $util.Long.prototype.toString.call(message.minConfirmations) : options.longs === Number ? new $util.LongBits(message.minConfirmations.low >>> 0, message.minConfirmations.high >>> 0).toNumber(true) : message.minConfirmations;
            if (message.createdAt != null && message.hasOwnProperty("createdAt"))
                if (typeof message.createdAt === "number")
                    object.createdAt = options.longs === String ? String(message.createdAt) : message.createdAt;
                else
                    object.createdAt = options.longs === String ? $util.Long.prototype.toString.call(message.createdAt) : options.longs === Number ? new $util.LongBits(message.createdAt.low >>> 0, message.createdAt.high >>> 0).toNumber(true) : message.createdAt;
            return object;
        };

        /**
         * Converts this ChannelProposal to JSON.
         * @function toJSON
         * @memberof p2p.ChannelProposal
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        ChannelProposal.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for ChannelProposal
         * @function getTypeUrl
         * @memberof p2p.ChannelProposal
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        ChannelProposal.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.ChannelProposal";
        };

        return ChannelProposal;
    })();

    p2p.CommitmentState = (function() {

        /**
         * Properties of a CommitmentState.
         * @memberof p2p
         * @interface ICommitmentState
         * @property {number|Long|null} [sequenceNumber] CommitmentState sequenceNumber
         * @property {number|null} [ownerPartyEnum] CommitmentState ownerPartyEnum
         * @property {number|Long|null} [ownerBalance] CommitmentState ownerBalance
         * @property {number|Long|null} [counterpartyBalance] CommitmentState counterpartyBalance
         * @property {p2p.ITransaction|null} [commitmentTx] CommitmentState commitmentTx
         * @property {Uint8Array|null} [ownerBlinding] CommitmentState ownerBlinding
         * @property {Uint8Array|null} [counterpartyBlinding] CommitmentState counterpartyBlinding
         * @property {p2p.IAdaptorSignature|null} [adaptorSignature] CommitmentState adaptorSignature
         * @property {Uint8Array|null} [revocationPoint] CommitmentState revocationPoint
         */

        /**
         * Constructs a new CommitmentState.
         * @memberof p2p
         * @classdesc Represents a CommitmentState.
         * @implements ICommitmentState
         * @constructor
         * @param {p2p.ICommitmentState=} [properties] Properties to set
         */
        function CommitmentState(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * CommitmentState sequenceNumber.
         * @member {number|Long} sequenceNumber
         * @memberof p2p.CommitmentState
         * @instance
         */
        CommitmentState.prototype.sequenceNumber = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * CommitmentState ownerPartyEnum.
         * @member {number} ownerPartyEnum
         * @memberof p2p.CommitmentState
         * @instance
         */
        CommitmentState.prototype.ownerPartyEnum = 0;

        /**
         * CommitmentState ownerBalance.
         * @member {number|Long} ownerBalance
         * @memberof p2p.CommitmentState
         * @instance
         */
        CommitmentState.prototype.ownerBalance = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * CommitmentState counterpartyBalance.
         * @member {number|Long} counterpartyBalance
         * @memberof p2p.CommitmentState
         * @instance
         */
        CommitmentState.prototype.counterpartyBalance = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * CommitmentState commitmentTx.
         * @member {p2p.ITransaction|null|undefined} commitmentTx
         * @memberof p2p.CommitmentState
         * @instance
         */
        CommitmentState.prototype.commitmentTx = null;

        /**
         * CommitmentState ownerBlinding.
         * @member {Uint8Array} ownerBlinding
         * @memberof p2p.CommitmentState
         * @instance
         */
        CommitmentState.prototype.ownerBlinding = $util.newBuffer([]);

        /**
         * CommitmentState counterpartyBlinding.
         * @member {Uint8Array} counterpartyBlinding
         * @memberof p2p.CommitmentState
         * @instance
         */
        CommitmentState.prototype.counterpartyBlinding = $util.newBuffer([]);

        /**
         * CommitmentState adaptorSignature.
         * @member {p2p.IAdaptorSignature|null|undefined} adaptorSignature
         * @memberof p2p.CommitmentState
         * @instance
         */
        CommitmentState.prototype.adaptorSignature = null;

        /**
         * CommitmentState revocationPoint.
         * @member {Uint8Array} revocationPoint
         * @memberof p2p.CommitmentState
         * @instance
         */
        CommitmentState.prototype.revocationPoint = $util.newBuffer([]);

        /**
         * Creates a new CommitmentState instance using the specified properties.
         * @function create
         * @memberof p2p.CommitmentState
         * @static
         * @param {p2p.ICommitmentState=} [properties] Properties to set
         * @returns {p2p.CommitmentState} CommitmentState instance
         */
        CommitmentState.create = function create(properties) {
            return new CommitmentState(properties);
        };

        /**
         * Encodes the specified CommitmentState message. Does not implicitly {@link p2p.CommitmentState.verify|verify} messages.
         * @function encode
         * @memberof p2p.CommitmentState
         * @static
         * @param {p2p.ICommitmentState} message CommitmentState message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        CommitmentState.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.sequenceNumber != null && Object.hasOwnProperty.call(message, "sequenceNumber"))
                writer.uint32(/* id 1, wireType 0 =*/8).uint64(message.sequenceNumber);
            if (message.ownerPartyEnum != null && Object.hasOwnProperty.call(message, "ownerPartyEnum"))
                writer.uint32(/* id 2, wireType 0 =*/16).uint32(message.ownerPartyEnum);
            if (message.ownerBalance != null && Object.hasOwnProperty.call(message, "ownerBalance"))
                writer.uint32(/* id 3, wireType 0 =*/24).uint64(message.ownerBalance);
            if (message.counterpartyBalance != null && Object.hasOwnProperty.call(message, "counterpartyBalance"))
                writer.uint32(/* id 4, wireType 0 =*/32).uint64(message.counterpartyBalance);
            if (message.commitmentTx != null && Object.hasOwnProperty.call(message, "commitmentTx"))
                $root.p2p.Transaction.encode(message.commitmentTx, writer.uint32(/* id 5, wireType 2 =*/42).fork()).ldelim();
            if (message.ownerBlinding != null && Object.hasOwnProperty.call(message, "ownerBlinding"))
                writer.uint32(/* id 6, wireType 2 =*/50).bytes(message.ownerBlinding);
            if (message.counterpartyBlinding != null && Object.hasOwnProperty.call(message, "counterpartyBlinding"))
                writer.uint32(/* id 7, wireType 2 =*/58).bytes(message.counterpartyBlinding);
            if (message.adaptorSignature != null && Object.hasOwnProperty.call(message, "adaptorSignature"))
                $root.p2p.AdaptorSignature.encode(message.adaptorSignature, writer.uint32(/* id 8, wireType 2 =*/66).fork()).ldelim();
            if (message.revocationPoint != null && Object.hasOwnProperty.call(message, "revocationPoint"))
                writer.uint32(/* id 9, wireType 2 =*/74).bytes(message.revocationPoint);
            return writer;
        };

        /**
         * Encodes the specified CommitmentState message, length delimited. Does not implicitly {@link p2p.CommitmentState.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.CommitmentState
         * @static
         * @param {p2p.ICommitmentState} message CommitmentState message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        CommitmentState.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a CommitmentState message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.CommitmentState
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.CommitmentState} CommitmentState
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        CommitmentState.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.CommitmentState();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.sequenceNumber = reader.uint64();
                        break;
                    }
                case 2: {
                        message.ownerPartyEnum = reader.uint32();
                        break;
                    }
                case 3: {
                        message.ownerBalance = reader.uint64();
                        break;
                    }
                case 4: {
                        message.counterpartyBalance = reader.uint64();
                        break;
                    }
                case 5: {
                        message.commitmentTx = $root.p2p.Transaction.decode(reader, reader.uint32());
                        break;
                    }
                case 6: {
                        message.ownerBlinding = reader.bytes();
                        break;
                    }
                case 7: {
                        message.counterpartyBlinding = reader.bytes();
                        break;
                    }
                case 8: {
                        message.adaptorSignature = $root.p2p.AdaptorSignature.decode(reader, reader.uint32());
                        break;
                    }
                case 9: {
                        message.revocationPoint = reader.bytes();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a CommitmentState message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.CommitmentState
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.CommitmentState} CommitmentState
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        CommitmentState.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a CommitmentState message.
         * @function verify
         * @memberof p2p.CommitmentState
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        CommitmentState.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.sequenceNumber != null && message.hasOwnProperty("sequenceNumber"))
                if (!$util.isInteger(message.sequenceNumber) && !(message.sequenceNumber && $util.isInteger(message.sequenceNumber.low) && $util.isInteger(message.sequenceNumber.high)))
                    return "sequenceNumber: integer|Long expected";
            if (message.ownerPartyEnum != null && message.hasOwnProperty("ownerPartyEnum"))
                if (!$util.isInteger(message.ownerPartyEnum))
                    return "ownerPartyEnum: integer expected";
            if (message.ownerBalance != null && message.hasOwnProperty("ownerBalance"))
                if (!$util.isInteger(message.ownerBalance) && !(message.ownerBalance && $util.isInteger(message.ownerBalance.low) && $util.isInteger(message.ownerBalance.high)))
                    return "ownerBalance: integer|Long expected";
            if (message.counterpartyBalance != null && message.hasOwnProperty("counterpartyBalance"))
                if (!$util.isInteger(message.counterpartyBalance) && !(message.counterpartyBalance && $util.isInteger(message.counterpartyBalance.low) && $util.isInteger(message.counterpartyBalance.high)))
                    return "counterpartyBalance: integer|Long expected";
            if (message.commitmentTx != null && message.hasOwnProperty("commitmentTx")) {
                var error = $root.p2p.Transaction.verify(message.commitmentTx);
                if (error)
                    return "commitmentTx." + error;
            }
            if (message.ownerBlinding != null && message.hasOwnProperty("ownerBlinding"))
                if (!(message.ownerBlinding && typeof message.ownerBlinding.length === "number" || $util.isString(message.ownerBlinding)))
                    return "ownerBlinding: buffer expected";
            if (message.counterpartyBlinding != null && message.hasOwnProperty("counterpartyBlinding"))
                if (!(message.counterpartyBlinding && typeof message.counterpartyBlinding.length === "number" || $util.isString(message.counterpartyBlinding)))
                    return "counterpartyBlinding: buffer expected";
            if (message.adaptorSignature != null && message.hasOwnProperty("adaptorSignature")) {
                var error = $root.p2p.AdaptorSignature.verify(message.adaptorSignature);
                if (error)
                    return "adaptorSignature." + error;
            }
            if (message.revocationPoint != null && message.hasOwnProperty("revocationPoint"))
                if (!(message.revocationPoint && typeof message.revocationPoint.length === "number" || $util.isString(message.revocationPoint)))
                    return "revocationPoint: buffer expected";
            return null;
        };

        /**
         * Creates a CommitmentState message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.CommitmentState
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.CommitmentState} CommitmentState
         */
        CommitmentState.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.CommitmentState)
                return object;
            var message = new $root.p2p.CommitmentState();
            if (object.sequenceNumber != null)
                if ($util.Long)
                    (message.sequenceNumber = $util.Long.fromValue(object.sequenceNumber)).unsigned = true;
                else if (typeof object.sequenceNumber === "string")
                    message.sequenceNumber = parseInt(object.sequenceNumber, 10);
                else if (typeof object.sequenceNumber === "number")
                    message.sequenceNumber = object.sequenceNumber;
                else if (typeof object.sequenceNumber === "object")
                    message.sequenceNumber = new $util.LongBits(object.sequenceNumber.low >>> 0, object.sequenceNumber.high >>> 0).toNumber(true);
            if (object.ownerPartyEnum != null)
                message.ownerPartyEnum = object.ownerPartyEnum >>> 0;
            if (object.ownerBalance != null)
                if ($util.Long)
                    (message.ownerBalance = $util.Long.fromValue(object.ownerBalance)).unsigned = true;
                else if (typeof object.ownerBalance === "string")
                    message.ownerBalance = parseInt(object.ownerBalance, 10);
                else if (typeof object.ownerBalance === "number")
                    message.ownerBalance = object.ownerBalance;
                else if (typeof object.ownerBalance === "object")
                    message.ownerBalance = new $util.LongBits(object.ownerBalance.low >>> 0, object.ownerBalance.high >>> 0).toNumber(true);
            if (object.counterpartyBalance != null)
                if ($util.Long)
                    (message.counterpartyBalance = $util.Long.fromValue(object.counterpartyBalance)).unsigned = true;
                else if (typeof object.counterpartyBalance === "string")
                    message.counterpartyBalance = parseInt(object.counterpartyBalance, 10);
                else if (typeof object.counterpartyBalance === "number")
                    message.counterpartyBalance = object.counterpartyBalance;
                else if (typeof object.counterpartyBalance === "object")
                    message.counterpartyBalance = new $util.LongBits(object.counterpartyBalance.low >>> 0, object.counterpartyBalance.high >>> 0).toNumber(true);
            if (object.commitmentTx != null) {
                if (typeof object.commitmentTx !== "object")
                    throw TypeError(".p2p.CommitmentState.commitmentTx: object expected");
                message.commitmentTx = $root.p2p.Transaction.fromObject(object.commitmentTx);
            }
            if (object.ownerBlinding != null)
                if (typeof object.ownerBlinding === "string")
                    $util.base64.decode(object.ownerBlinding, message.ownerBlinding = $util.newBuffer($util.base64.length(object.ownerBlinding)), 0);
                else if (object.ownerBlinding.length >= 0)
                    message.ownerBlinding = object.ownerBlinding;
            if (object.counterpartyBlinding != null)
                if (typeof object.counterpartyBlinding === "string")
                    $util.base64.decode(object.counterpartyBlinding, message.counterpartyBlinding = $util.newBuffer($util.base64.length(object.counterpartyBlinding)), 0);
                else if (object.counterpartyBlinding.length >= 0)
                    message.counterpartyBlinding = object.counterpartyBlinding;
            if (object.adaptorSignature != null) {
                if (typeof object.adaptorSignature !== "object")
                    throw TypeError(".p2p.CommitmentState.adaptorSignature: object expected");
                message.adaptorSignature = $root.p2p.AdaptorSignature.fromObject(object.adaptorSignature);
            }
            if (object.revocationPoint != null)
                if (typeof object.revocationPoint === "string")
                    $util.base64.decode(object.revocationPoint, message.revocationPoint = $util.newBuffer($util.base64.length(object.revocationPoint)), 0);
                else if (object.revocationPoint.length >= 0)
                    message.revocationPoint = object.revocationPoint;
            return message;
        };

        /**
         * Creates a plain object from a CommitmentState message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.CommitmentState
         * @static
         * @param {p2p.CommitmentState} message CommitmentState
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        CommitmentState.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.sequenceNumber = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.sequenceNumber = options.longs === String ? "0" : 0;
                object.ownerPartyEnum = 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.ownerBalance = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.ownerBalance = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.counterpartyBalance = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.counterpartyBalance = options.longs === String ? "0" : 0;
                object.commitmentTx = null;
                if (options.bytes === String)
                    object.ownerBlinding = "";
                else {
                    object.ownerBlinding = [];
                    if (options.bytes !== Array)
                        object.ownerBlinding = $util.newBuffer(object.ownerBlinding);
                }
                if (options.bytes === String)
                    object.counterpartyBlinding = "";
                else {
                    object.counterpartyBlinding = [];
                    if (options.bytes !== Array)
                        object.counterpartyBlinding = $util.newBuffer(object.counterpartyBlinding);
                }
                object.adaptorSignature = null;
                if (options.bytes === String)
                    object.revocationPoint = "";
                else {
                    object.revocationPoint = [];
                    if (options.bytes !== Array)
                        object.revocationPoint = $util.newBuffer(object.revocationPoint);
                }
            }
            if (message.sequenceNumber != null && message.hasOwnProperty("sequenceNumber"))
                if (typeof message.sequenceNumber === "number")
                    object.sequenceNumber = options.longs === String ? String(message.sequenceNumber) : message.sequenceNumber;
                else
                    object.sequenceNumber = options.longs === String ? $util.Long.prototype.toString.call(message.sequenceNumber) : options.longs === Number ? new $util.LongBits(message.sequenceNumber.low >>> 0, message.sequenceNumber.high >>> 0).toNumber(true) : message.sequenceNumber;
            if (message.ownerPartyEnum != null && message.hasOwnProperty("ownerPartyEnum"))
                object.ownerPartyEnum = message.ownerPartyEnum;
            if (message.ownerBalance != null && message.hasOwnProperty("ownerBalance"))
                if (typeof message.ownerBalance === "number")
                    object.ownerBalance = options.longs === String ? String(message.ownerBalance) : message.ownerBalance;
                else
                    object.ownerBalance = options.longs === String ? $util.Long.prototype.toString.call(message.ownerBalance) : options.longs === Number ? new $util.LongBits(message.ownerBalance.low >>> 0, message.ownerBalance.high >>> 0).toNumber(true) : message.ownerBalance;
            if (message.counterpartyBalance != null && message.hasOwnProperty("counterpartyBalance"))
                if (typeof message.counterpartyBalance === "number")
                    object.counterpartyBalance = options.longs === String ? String(message.counterpartyBalance) : message.counterpartyBalance;
                else
                    object.counterpartyBalance = options.longs === String ? $util.Long.prototype.toString.call(message.counterpartyBalance) : options.longs === Number ? new $util.LongBits(message.counterpartyBalance.low >>> 0, message.counterpartyBalance.high >>> 0).toNumber(true) : message.counterpartyBalance;
            if (message.commitmentTx != null && message.hasOwnProperty("commitmentTx"))
                object.commitmentTx = $root.p2p.Transaction.toObject(message.commitmentTx, options);
            if (message.ownerBlinding != null && message.hasOwnProperty("ownerBlinding"))
                object.ownerBlinding = options.bytes === String ? $util.base64.encode(message.ownerBlinding, 0, message.ownerBlinding.length) : options.bytes === Array ? Array.prototype.slice.call(message.ownerBlinding) : message.ownerBlinding;
            if (message.counterpartyBlinding != null && message.hasOwnProperty("counterpartyBlinding"))
                object.counterpartyBlinding = options.bytes === String ? $util.base64.encode(message.counterpartyBlinding, 0, message.counterpartyBlinding.length) : options.bytes === Array ? Array.prototype.slice.call(message.counterpartyBlinding) : message.counterpartyBlinding;
            if (message.adaptorSignature != null && message.hasOwnProperty("adaptorSignature"))
                object.adaptorSignature = $root.p2p.AdaptorSignature.toObject(message.adaptorSignature, options);
            if (message.revocationPoint != null && message.hasOwnProperty("revocationPoint"))
                object.revocationPoint = options.bytes === String ? $util.base64.encode(message.revocationPoint, 0, message.revocationPoint.length) : options.bytes === Array ? Array.prototype.slice.call(message.revocationPoint) : message.revocationPoint;
            return object;
        };

        /**
         * Converts this CommitmentState to JSON.
         * @function toJSON
         * @memberof p2p.CommitmentState
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        CommitmentState.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for CommitmentState
         * @function getTypeUrl
         * @memberof p2p.CommitmentState
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        CommitmentState.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.CommitmentState";
        };

        return CommitmentState;
    })();

    p2p.ChannelAcceptance = (function() {

        /**
         * Properties of a ChannelAcceptance.
         * @memberof p2p
         * @interface IChannelAcceptance
         * @property {Uint8Array|null} [channelId] ChannelAcceptance channelId
         * @property {p2p.ICommitmentState|null} [partyBCommitment] ChannelAcceptance partyBCommitment
         * @property {Uint8Array|null} [partyBRevocationPoint] ChannelAcceptance partyBRevocationPoint
         * @property {number|Long|null} [acceptedAt] ChannelAcceptance acceptedAt
         */

        /**
         * Constructs a new ChannelAcceptance.
         * @memberof p2p
         * @classdesc Represents a ChannelAcceptance.
         * @implements IChannelAcceptance
         * @constructor
         * @param {p2p.IChannelAcceptance=} [properties] Properties to set
         */
        function ChannelAcceptance(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * ChannelAcceptance channelId.
         * @member {Uint8Array} channelId
         * @memberof p2p.ChannelAcceptance
         * @instance
         */
        ChannelAcceptance.prototype.channelId = $util.newBuffer([]);

        /**
         * ChannelAcceptance partyBCommitment.
         * @member {p2p.ICommitmentState|null|undefined} partyBCommitment
         * @memberof p2p.ChannelAcceptance
         * @instance
         */
        ChannelAcceptance.prototype.partyBCommitment = null;

        /**
         * ChannelAcceptance partyBRevocationPoint.
         * @member {Uint8Array} partyBRevocationPoint
         * @memberof p2p.ChannelAcceptance
         * @instance
         */
        ChannelAcceptance.prototype.partyBRevocationPoint = $util.newBuffer([]);

        /**
         * ChannelAcceptance acceptedAt.
         * @member {number|Long} acceptedAt
         * @memberof p2p.ChannelAcceptance
         * @instance
         */
        ChannelAcceptance.prototype.acceptedAt = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Creates a new ChannelAcceptance instance using the specified properties.
         * @function create
         * @memberof p2p.ChannelAcceptance
         * @static
         * @param {p2p.IChannelAcceptance=} [properties] Properties to set
         * @returns {p2p.ChannelAcceptance} ChannelAcceptance instance
         */
        ChannelAcceptance.create = function create(properties) {
            return new ChannelAcceptance(properties);
        };

        /**
         * Encodes the specified ChannelAcceptance message. Does not implicitly {@link p2p.ChannelAcceptance.verify|verify} messages.
         * @function encode
         * @memberof p2p.ChannelAcceptance
         * @static
         * @param {p2p.IChannelAcceptance} message ChannelAcceptance message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        ChannelAcceptance.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.channelId != null && Object.hasOwnProperty.call(message, "channelId"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.channelId);
            if (message.partyBCommitment != null && Object.hasOwnProperty.call(message, "partyBCommitment"))
                $root.p2p.CommitmentState.encode(message.partyBCommitment, writer.uint32(/* id 2, wireType 2 =*/18).fork()).ldelim();
            if (message.partyBRevocationPoint != null && Object.hasOwnProperty.call(message, "partyBRevocationPoint"))
                writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.partyBRevocationPoint);
            if (message.acceptedAt != null && Object.hasOwnProperty.call(message, "acceptedAt"))
                writer.uint32(/* id 4, wireType 0 =*/32).uint64(message.acceptedAt);
            return writer;
        };

        /**
         * Encodes the specified ChannelAcceptance message, length delimited. Does not implicitly {@link p2p.ChannelAcceptance.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.ChannelAcceptance
         * @static
         * @param {p2p.IChannelAcceptance} message ChannelAcceptance message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        ChannelAcceptance.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a ChannelAcceptance message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.ChannelAcceptance
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.ChannelAcceptance} ChannelAcceptance
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        ChannelAcceptance.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.ChannelAcceptance();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.channelId = reader.bytes();
                        break;
                    }
                case 2: {
                        message.partyBCommitment = $root.p2p.CommitmentState.decode(reader, reader.uint32());
                        break;
                    }
                case 3: {
                        message.partyBRevocationPoint = reader.bytes();
                        break;
                    }
                case 4: {
                        message.acceptedAt = reader.uint64();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a ChannelAcceptance message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.ChannelAcceptance
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.ChannelAcceptance} ChannelAcceptance
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        ChannelAcceptance.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a ChannelAcceptance message.
         * @function verify
         * @memberof p2p.ChannelAcceptance
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        ChannelAcceptance.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.channelId != null && message.hasOwnProperty("channelId"))
                if (!(message.channelId && typeof message.channelId.length === "number" || $util.isString(message.channelId)))
                    return "channelId: buffer expected";
            if (message.partyBCommitment != null && message.hasOwnProperty("partyBCommitment")) {
                var error = $root.p2p.CommitmentState.verify(message.partyBCommitment);
                if (error)
                    return "partyBCommitment." + error;
            }
            if (message.partyBRevocationPoint != null && message.hasOwnProperty("partyBRevocationPoint"))
                if (!(message.partyBRevocationPoint && typeof message.partyBRevocationPoint.length === "number" || $util.isString(message.partyBRevocationPoint)))
                    return "partyBRevocationPoint: buffer expected";
            if (message.acceptedAt != null && message.hasOwnProperty("acceptedAt"))
                if (!$util.isInteger(message.acceptedAt) && !(message.acceptedAt && $util.isInteger(message.acceptedAt.low) && $util.isInteger(message.acceptedAt.high)))
                    return "acceptedAt: integer|Long expected";
            return null;
        };

        /**
         * Creates a ChannelAcceptance message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.ChannelAcceptance
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.ChannelAcceptance} ChannelAcceptance
         */
        ChannelAcceptance.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.ChannelAcceptance)
                return object;
            var message = new $root.p2p.ChannelAcceptance();
            if (object.channelId != null)
                if (typeof object.channelId === "string")
                    $util.base64.decode(object.channelId, message.channelId = $util.newBuffer($util.base64.length(object.channelId)), 0);
                else if (object.channelId.length >= 0)
                    message.channelId = object.channelId;
            if (object.partyBCommitment != null) {
                if (typeof object.partyBCommitment !== "object")
                    throw TypeError(".p2p.ChannelAcceptance.partyBCommitment: object expected");
                message.partyBCommitment = $root.p2p.CommitmentState.fromObject(object.partyBCommitment);
            }
            if (object.partyBRevocationPoint != null)
                if (typeof object.partyBRevocationPoint === "string")
                    $util.base64.decode(object.partyBRevocationPoint, message.partyBRevocationPoint = $util.newBuffer($util.base64.length(object.partyBRevocationPoint)), 0);
                else if (object.partyBRevocationPoint.length >= 0)
                    message.partyBRevocationPoint = object.partyBRevocationPoint;
            if (object.acceptedAt != null)
                if ($util.Long)
                    (message.acceptedAt = $util.Long.fromValue(object.acceptedAt)).unsigned = true;
                else if (typeof object.acceptedAt === "string")
                    message.acceptedAt = parseInt(object.acceptedAt, 10);
                else if (typeof object.acceptedAt === "number")
                    message.acceptedAt = object.acceptedAt;
                else if (typeof object.acceptedAt === "object")
                    message.acceptedAt = new $util.LongBits(object.acceptedAt.low >>> 0, object.acceptedAt.high >>> 0).toNumber(true);
            return message;
        };

        /**
         * Creates a plain object from a ChannelAcceptance message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.ChannelAcceptance
         * @static
         * @param {p2p.ChannelAcceptance} message ChannelAcceptance
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        ChannelAcceptance.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.channelId = "";
                else {
                    object.channelId = [];
                    if (options.bytes !== Array)
                        object.channelId = $util.newBuffer(object.channelId);
                }
                object.partyBCommitment = null;
                if (options.bytes === String)
                    object.partyBRevocationPoint = "";
                else {
                    object.partyBRevocationPoint = [];
                    if (options.bytes !== Array)
                        object.partyBRevocationPoint = $util.newBuffer(object.partyBRevocationPoint);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.acceptedAt = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.acceptedAt = options.longs === String ? "0" : 0;
            }
            if (message.channelId != null && message.hasOwnProperty("channelId"))
                object.channelId = options.bytes === String ? $util.base64.encode(message.channelId, 0, message.channelId.length) : options.bytes === Array ? Array.prototype.slice.call(message.channelId) : message.channelId;
            if (message.partyBCommitment != null && message.hasOwnProperty("partyBCommitment"))
                object.partyBCommitment = $root.p2p.CommitmentState.toObject(message.partyBCommitment, options);
            if (message.partyBRevocationPoint != null && message.hasOwnProperty("partyBRevocationPoint"))
                object.partyBRevocationPoint = options.bytes === String ? $util.base64.encode(message.partyBRevocationPoint, 0, message.partyBRevocationPoint.length) : options.bytes === Array ? Array.prototype.slice.call(message.partyBRevocationPoint) : message.partyBRevocationPoint;
            if (message.acceptedAt != null && message.hasOwnProperty("acceptedAt"))
                if (typeof message.acceptedAt === "number")
                    object.acceptedAt = options.longs === String ? String(message.acceptedAt) : message.acceptedAt;
                else
                    object.acceptedAt = options.longs === String ? $util.Long.prototype.toString.call(message.acceptedAt) : options.longs === Number ? new $util.LongBits(message.acceptedAt.low >>> 0, message.acceptedAt.high >>> 0).toNumber(true) : message.acceptedAt;
            return object;
        };

        /**
         * Converts this ChannelAcceptance to JSON.
         * @function toJSON
         * @memberof p2p.ChannelAcceptance
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        ChannelAcceptance.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for ChannelAcceptance
         * @function getTypeUrl
         * @memberof p2p.ChannelAcceptance
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        ChannelAcceptance.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.ChannelAcceptance";
        };

        return ChannelAcceptance;
    })();

    p2p.ChannelNonce = (function() {

        /**
         * Properties of a ChannelNonce.
         * @memberof p2p
         * @interface IChannelNonce
         * @property {Uint8Array|null} [channelId] ChannelNonce channelId
         * @property {Uint8Array|null} [publicNoncePoint] ChannelNonce publicNoncePoint
         */

        /**
         * Constructs a new ChannelNonce.
         * @memberof p2p
         * @classdesc Represents a ChannelNonce.
         * @implements IChannelNonce
         * @constructor
         * @param {p2p.IChannelNonce=} [properties] Properties to set
         */
        function ChannelNonce(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * ChannelNonce channelId.
         * @member {Uint8Array} channelId
         * @memberof p2p.ChannelNonce
         * @instance
         */
        ChannelNonce.prototype.channelId = $util.newBuffer([]);

        /**
         * ChannelNonce publicNoncePoint.
         * @member {Uint8Array} publicNoncePoint
         * @memberof p2p.ChannelNonce
         * @instance
         */
        ChannelNonce.prototype.publicNoncePoint = $util.newBuffer([]);

        /**
         * Creates a new ChannelNonce instance using the specified properties.
         * @function create
         * @memberof p2p.ChannelNonce
         * @static
         * @param {p2p.IChannelNonce=} [properties] Properties to set
         * @returns {p2p.ChannelNonce} ChannelNonce instance
         */
        ChannelNonce.create = function create(properties) {
            return new ChannelNonce(properties);
        };

        /**
         * Encodes the specified ChannelNonce message. Does not implicitly {@link p2p.ChannelNonce.verify|verify} messages.
         * @function encode
         * @memberof p2p.ChannelNonce
         * @static
         * @param {p2p.IChannelNonce} message ChannelNonce message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        ChannelNonce.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.channelId != null && Object.hasOwnProperty.call(message, "channelId"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.channelId);
            if (message.publicNoncePoint != null && Object.hasOwnProperty.call(message, "publicNoncePoint"))
                writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.publicNoncePoint);
            return writer;
        };

        /**
         * Encodes the specified ChannelNonce message, length delimited. Does not implicitly {@link p2p.ChannelNonce.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.ChannelNonce
         * @static
         * @param {p2p.IChannelNonce} message ChannelNonce message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        ChannelNonce.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a ChannelNonce message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.ChannelNonce
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.ChannelNonce} ChannelNonce
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        ChannelNonce.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.ChannelNonce();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.channelId = reader.bytes();
                        break;
                    }
                case 2: {
                        message.publicNoncePoint = reader.bytes();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a ChannelNonce message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.ChannelNonce
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.ChannelNonce} ChannelNonce
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        ChannelNonce.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a ChannelNonce message.
         * @function verify
         * @memberof p2p.ChannelNonce
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        ChannelNonce.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.channelId != null && message.hasOwnProperty("channelId"))
                if (!(message.channelId && typeof message.channelId.length === "number" || $util.isString(message.channelId)))
                    return "channelId: buffer expected";
            if (message.publicNoncePoint != null && message.hasOwnProperty("publicNoncePoint"))
                if (!(message.publicNoncePoint && typeof message.publicNoncePoint.length === "number" || $util.isString(message.publicNoncePoint)))
                    return "publicNoncePoint: buffer expected";
            return null;
        };

        /**
         * Creates a ChannelNonce message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.ChannelNonce
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.ChannelNonce} ChannelNonce
         */
        ChannelNonce.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.ChannelNonce)
                return object;
            var message = new $root.p2p.ChannelNonce();
            if (object.channelId != null)
                if (typeof object.channelId === "string")
                    $util.base64.decode(object.channelId, message.channelId = $util.newBuffer($util.base64.length(object.channelId)), 0);
                else if (object.channelId.length >= 0)
                    message.channelId = object.channelId;
            if (object.publicNoncePoint != null)
                if (typeof object.publicNoncePoint === "string")
                    $util.base64.decode(object.publicNoncePoint, message.publicNoncePoint = $util.newBuffer($util.base64.length(object.publicNoncePoint)), 0);
                else if (object.publicNoncePoint.length >= 0)
                    message.publicNoncePoint = object.publicNoncePoint;
            return message;
        };

        /**
         * Creates a plain object from a ChannelNonce message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.ChannelNonce
         * @static
         * @param {p2p.ChannelNonce} message ChannelNonce
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        ChannelNonce.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.channelId = "";
                else {
                    object.channelId = [];
                    if (options.bytes !== Array)
                        object.channelId = $util.newBuffer(object.channelId);
                }
                if (options.bytes === String)
                    object.publicNoncePoint = "";
                else {
                    object.publicNoncePoint = [];
                    if (options.bytes !== Array)
                        object.publicNoncePoint = $util.newBuffer(object.publicNoncePoint);
                }
            }
            if (message.channelId != null && message.hasOwnProperty("channelId"))
                object.channelId = options.bytes === String ? $util.base64.encode(message.channelId, 0, message.channelId.length) : options.bytes === Array ? Array.prototype.slice.call(message.channelId) : message.channelId;
            if (message.publicNoncePoint != null && message.hasOwnProperty("publicNoncePoint"))
                object.publicNoncePoint = options.bytes === String ? $util.base64.encode(message.publicNoncePoint, 0, message.publicNoncePoint.length) : options.bytes === Array ? Array.prototype.slice.call(message.publicNoncePoint) : message.publicNoncePoint;
            return object;
        };

        /**
         * Converts this ChannelNonce to JSON.
         * @function toJSON
         * @memberof p2p.ChannelNonce
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        ChannelNonce.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for ChannelNonce
         * @function getTypeUrl
         * @memberof p2p.ChannelNonce
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        ChannelNonce.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.ChannelNonce";
        };

        return ChannelNonce;
    })();

    p2p.ChannelPartialSig = (function() {

        /**
         * Properties of a ChannelPartialSig.
         * @memberof p2p
         * @interface IChannelPartialSig
         * @property {Uint8Array|null} [channelId] ChannelPartialSig channelId
         * @property {Uint8Array|null} [partialSignature] ChannelPartialSig partialSignature
         * @property {p2p.ITransaction|null} [fundingTx] ChannelPartialSig fundingTx
         */

        /**
         * Constructs a new ChannelPartialSig.
         * @memberof p2p
         * @classdesc Represents a ChannelPartialSig.
         * @implements IChannelPartialSig
         * @constructor
         * @param {p2p.IChannelPartialSig=} [properties] Properties to set
         */
        function ChannelPartialSig(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * ChannelPartialSig channelId.
         * @member {Uint8Array} channelId
         * @memberof p2p.ChannelPartialSig
         * @instance
         */
        ChannelPartialSig.prototype.channelId = $util.newBuffer([]);

        /**
         * ChannelPartialSig partialSignature.
         * @member {Uint8Array} partialSignature
         * @memberof p2p.ChannelPartialSig
         * @instance
         */
        ChannelPartialSig.prototype.partialSignature = $util.newBuffer([]);

        /**
         * ChannelPartialSig fundingTx.
         * @member {p2p.ITransaction|null|undefined} fundingTx
         * @memberof p2p.ChannelPartialSig
         * @instance
         */
        ChannelPartialSig.prototype.fundingTx = null;

        /**
         * Creates a new ChannelPartialSig instance using the specified properties.
         * @function create
         * @memberof p2p.ChannelPartialSig
         * @static
         * @param {p2p.IChannelPartialSig=} [properties] Properties to set
         * @returns {p2p.ChannelPartialSig} ChannelPartialSig instance
         */
        ChannelPartialSig.create = function create(properties) {
            return new ChannelPartialSig(properties);
        };

        /**
         * Encodes the specified ChannelPartialSig message. Does not implicitly {@link p2p.ChannelPartialSig.verify|verify} messages.
         * @function encode
         * @memberof p2p.ChannelPartialSig
         * @static
         * @param {p2p.IChannelPartialSig} message ChannelPartialSig message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        ChannelPartialSig.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.channelId != null && Object.hasOwnProperty.call(message, "channelId"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.channelId);
            if (message.partialSignature != null && Object.hasOwnProperty.call(message, "partialSignature"))
                writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.partialSignature);
            if (message.fundingTx != null && Object.hasOwnProperty.call(message, "fundingTx"))
                $root.p2p.Transaction.encode(message.fundingTx, writer.uint32(/* id 3, wireType 2 =*/26).fork()).ldelim();
            return writer;
        };

        /**
         * Encodes the specified ChannelPartialSig message, length delimited. Does not implicitly {@link p2p.ChannelPartialSig.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.ChannelPartialSig
         * @static
         * @param {p2p.IChannelPartialSig} message ChannelPartialSig message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        ChannelPartialSig.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a ChannelPartialSig message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.ChannelPartialSig
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.ChannelPartialSig} ChannelPartialSig
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        ChannelPartialSig.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.ChannelPartialSig();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.channelId = reader.bytes();
                        break;
                    }
                case 2: {
                        message.partialSignature = reader.bytes();
                        break;
                    }
                case 3: {
                        message.fundingTx = $root.p2p.Transaction.decode(reader, reader.uint32());
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a ChannelPartialSig message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.ChannelPartialSig
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.ChannelPartialSig} ChannelPartialSig
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        ChannelPartialSig.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a ChannelPartialSig message.
         * @function verify
         * @memberof p2p.ChannelPartialSig
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        ChannelPartialSig.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.channelId != null && message.hasOwnProperty("channelId"))
                if (!(message.channelId && typeof message.channelId.length === "number" || $util.isString(message.channelId)))
                    return "channelId: buffer expected";
            if (message.partialSignature != null && message.hasOwnProperty("partialSignature"))
                if (!(message.partialSignature && typeof message.partialSignature.length === "number" || $util.isString(message.partialSignature)))
                    return "partialSignature: buffer expected";
            if (message.fundingTx != null && message.hasOwnProperty("fundingTx")) {
                var error = $root.p2p.Transaction.verify(message.fundingTx);
                if (error)
                    return "fundingTx." + error;
            }
            return null;
        };

        /**
         * Creates a ChannelPartialSig message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.ChannelPartialSig
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.ChannelPartialSig} ChannelPartialSig
         */
        ChannelPartialSig.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.ChannelPartialSig)
                return object;
            var message = new $root.p2p.ChannelPartialSig();
            if (object.channelId != null)
                if (typeof object.channelId === "string")
                    $util.base64.decode(object.channelId, message.channelId = $util.newBuffer($util.base64.length(object.channelId)), 0);
                else if (object.channelId.length >= 0)
                    message.channelId = object.channelId;
            if (object.partialSignature != null)
                if (typeof object.partialSignature === "string")
                    $util.base64.decode(object.partialSignature, message.partialSignature = $util.newBuffer($util.base64.length(object.partialSignature)), 0);
                else if (object.partialSignature.length >= 0)
                    message.partialSignature = object.partialSignature;
            if (object.fundingTx != null) {
                if (typeof object.fundingTx !== "object")
                    throw TypeError(".p2p.ChannelPartialSig.fundingTx: object expected");
                message.fundingTx = $root.p2p.Transaction.fromObject(object.fundingTx);
            }
            return message;
        };

        /**
         * Creates a plain object from a ChannelPartialSig message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.ChannelPartialSig
         * @static
         * @param {p2p.ChannelPartialSig} message ChannelPartialSig
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        ChannelPartialSig.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.channelId = "";
                else {
                    object.channelId = [];
                    if (options.bytes !== Array)
                        object.channelId = $util.newBuffer(object.channelId);
                }
                if (options.bytes === String)
                    object.partialSignature = "";
                else {
                    object.partialSignature = [];
                    if (options.bytes !== Array)
                        object.partialSignature = $util.newBuffer(object.partialSignature);
                }
                object.fundingTx = null;
            }
            if (message.channelId != null && message.hasOwnProperty("channelId"))
                object.channelId = options.bytes === String ? $util.base64.encode(message.channelId, 0, message.channelId.length) : options.bytes === Array ? Array.prototype.slice.call(message.channelId) : message.channelId;
            if (message.partialSignature != null && message.hasOwnProperty("partialSignature"))
                object.partialSignature = options.bytes === String ? $util.base64.encode(message.partialSignature, 0, message.partialSignature.length) : options.bytes === Array ? Array.prototype.slice.call(message.partialSignature) : message.partialSignature;
            if (message.fundingTx != null && message.hasOwnProperty("fundingTx"))
                object.fundingTx = $root.p2p.Transaction.toObject(message.fundingTx, options);
            return object;
        };

        /**
         * Converts this ChannelPartialSig to JSON.
         * @function toJSON
         * @memberof p2p.ChannelPartialSig
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        ChannelPartialSig.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for ChannelPartialSig
         * @function getTypeUrl
         * @memberof p2p.ChannelPartialSig
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        ChannelPartialSig.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.ChannelPartialSig";
        };

        return ChannelPartialSig;
    })();

    p2p.RevocationData = (function() {

        /**
         * Properties of a RevocationData.
         * @memberof p2p
         * @interface IRevocationData
         * @property {number|null} [partyEnum] RevocationData partyEnum
         * @property {number|Long|null} [sequenceNumber] RevocationData sequenceNumber
         * @property {Uint8Array|null} [revocationSecret] RevocationData revocationSecret
         * @property {Uint8Array|null} [revocationPoint] RevocationData revocationPoint
         * @property {number|Long|null} [revokedAt] RevocationData revokedAt
         */

        /**
         * Constructs a new RevocationData.
         * @memberof p2p
         * @classdesc Represents a RevocationData.
         * @implements IRevocationData
         * @constructor
         * @param {p2p.IRevocationData=} [properties] Properties to set
         */
        function RevocationData(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * RevocationData partyEnum.
         * @member {number} partyEnum
         * @memberof p2p.RevocationData
         * @instance
         */
        RevocationData.prototype.partyEnum = 0;

        /**
         * RevocationData sequenceNumber.
         * @member {number|Long} sequenceNumber
         * @memberof p2p.RevocationData
         * @instance
         */
        RevocationData.prototype.sequenceNumber = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * RevocationData revocationSecret.
         * @member {Uint8Array} revocationSecret
         * @memberof p2p.RevocationData
         * @instance
         */
        RevocationData.prototype.revocationSecret = $util.newBuffer([]);

        /**
         * RevocationData revocationPoint.
         * @member {Uint8Array} revocationPoint
         * @memberof p2p.RevocationData
         * @instance
         */
        RevocationData.prototype.revocationPoint = $util.newBuffer([]);

        /**
         * RevocationData revokedAt.
         * @member {number|Long} revokedAt
         * @memberof p2p.RevocationData
         * @instance
         */
        RevocationData.prototype.revokedAt = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * Creates a new RevocationData instance using the specified properties.
         * @function create
         * @memberof p2p.RevocationData
         * @static
         * @param {p2p.IRevocationData=} [properties] Properties to set
         * @returns {p2p.RevocationData} RevocationData instance
         */
        RevocationData.create = function create(properties) {
            return new RevocationData(properties);
        };

        /**
         * Encodes the specified RevocationData message. Does not implicitly {@link p2p.RevocationData.verify|verify} messages.
         * @function encode
         * @memberof p2p.RevocationData
         * @static
         * @param {p2p.IRevocationData} message RevocationData message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        RevocationData.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.partyEnum != null && Object.hasOwnProperty.call(message, "partyEnum"))
                writer.uint32(/* id 1, wireType 0 =*/8).uint32(message.partyEnum);
            if (message.sequenceNumber != null && Object.hasOwnProperty.call(message, "sequenceNumber"))
                writer.uint32(/* id 2, wireType 0 =*/16).uint64(message.sequenceNumber);
            if (message.revocationSecret != null && Object.hasOwnProperty.call(message, "revocationSecret"))
                writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.revocationSecret);
            if (message.revocationPoint != null && Object.hasOwnProperty.call(message, "revocationPoint"))
                writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.revocationPoint);
            if (message.revokedAt != null && Object.hasOwnProperty.call(message, "revokedAt"))
                writer.uint32(/* id 5, wireType 0 =*/40).uint64(message.revokedAt);
            return writer;
        };

        /**
         * Encodes the specified RevocationData message, length delimited. Does not implicitly {@link p2p.RevocationData.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.RevocationData
         * @static
         * @param {p2p.IRevocationData} message RevocationData message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        RevocationData.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a RevocationData message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.RevocationData
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.RevocationData} RevocationData
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        RevocationData.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.RevocationData();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.partyEnum = reader.uint32();
                        break;
                    }
                case 2: {
                        message.sequenceNumber = reader.uint64();
                        break;
                    }
                case 3: {
                        message.revocationSecret = reader.bytes();
                        break;
                    }
                case 4: {
                        message.revocationPoint = reader.bytes();
                        break;
                    }
                case 5: {
                        message.revokedAt = reader.uint64();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a RevocationData message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.RevocationData
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.RevocationData} RevocationData
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        RevocationData.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a RevocationData message.
         * @function verify
         * @memberof p2p.RevocationData
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        RevocationData.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            if (message.partyEnum != null && message.hasOwnProperty("partyEnum"))
                if (!$util.isInteger(message.partyEnum))
                    return "partyEnum: integer expected";
            if (message.sequenceNumber != null && message.hasOwnProperty("sequenceNumber"))
                if (!$util.isInteger(message.sequenceNumber) && !(message.sequenceNumber && $util.isInteger(message.sequenceNumber.low) && $util.isInteger(message.sequenceNumber.high)))
                    return "sequenceNumber: integer|Long expected";
            if (message.revocationSecret != null && message.hasOwnProperty("revocationSecret"))
                if (!(message.revocationSecret && typeof message.revocationSecret.length === "number" || $util.isString(message.revocationSecret)))
                    return "revocationSecret: buffer expected";
            if (message.revocationPoint != null && message.hasOwnProperty("revocationPoint"))
                if (!(message.revocationPoint && typeof message.revocationPoint.length === "number" || $util.isString(message.revocationPoint)))
                    return "revocationPoint: buffer expected";
            if (message.revokedAt != null && message.hasOwnProperty("revokedAt"))
                if (!$util.isInteger(message.revokedAt) && !(message.revokedAt && $util.isInteger(message.revokedAt.low) && $util.isInteger(message.revokedAt.high)))
                    return "revokedAt: integer|Long expected";
            return null;
        };

        /**
         * Creates a RevocationData message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.RevocationData
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.RevocationData} RevocationData
         */
        RevocationData.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.RevocationData)
                return object;
            var message = new $root.p2p.RevocationData();
            if (object.partyEnum != null)
                message.partyEnum = object.partyEnum >>> 0;
            if (object.sequenceNumber != null)
                if ($util.Long)
                    (message.sequenceNumber = $util.Long.fromValue(object.sequenceNumber)).unsigned = true;
                else if (typeof object.sequenceNumber === "string")
                    message.sequenceNumber = parseInt(object.sequenceNumber, 10);
                else if (typeof object.sequenceNumber === "number")
                    message.sequenceNumber = object.sequenceNumber;
                else if (typeof object.sequenceNumber === "object")
                    message.sequenceNumber = new $util.LongBits(object.sequenceNumber.low >>> 0, object.sequenceNumber.high >>> 0).toNumber(true);
            if (object.revocationSecret != null)
                if (typeof object.revocationSecret === "string")
                    $util.base64.decode(object.revocationSecret, message.revocationSecret = $util.newBuffer($util.base64.length(object.revocationSecret)), 0);
                else if (object.revocationSecret.length >= 0)
                    message.revocationSecret = object.revocationSecret;
            if (object.revocationPoint != null)
                if (typeof object.revocationPoint === "string")
                    $util.base64.decode(object.revocationPoint, message.revocationPoint = $util.newBuffer($util.base64.length(object.revocationPoint)), 0);
                else if (object.revocationPoint.length >= 0)
                    message.revocationPoint = object.revocationPoint;
            if (object.revokedAt != null)
                if ($util.Long)
                    (message.revokedAt = $util.Long.fromValue(object.revokedAt)).unsigned = true;
                else if (typeof object.revokedAt === "string")
                    message.revokedAt = parseInt(object.revokedAt, 10);
                else if (typeof object.revokedAt === "number")
                    message.revokedAt = object.revokedAt;
                else if (typeof object.revokedAt === "object")
                    message.revokedAt = new $util.LongBits(object.revokedAt.low >>> 0, object.revokedAt.high >>> 0).toNumber(true);
            return message;
        };

        /**
         * Creates a plain object from a RevocationData message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.RevocationData
         * @static
         * @param {p2p.RevocationData} message RevocationData
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        RevocationData.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                object.partyEnum = 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.sequenceNumber = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.sequenceNumber = options.longs === String ? "0" : 0;
                if (options.bytes === String)
                    object.revocationSecret = "";
                else {
                    object.revocationSecret = [];
                    if (options.bytes !== Array)
                        object.revocationSecret = $util.newBuffer(object.revocationSecret);
                }
                if (options.bytes === String)
                    object.revocationPoint = "";
                else {
                    object.revocationPoint = [];
                    if (options.bytes !== Array)
                        object.revocationPoint = $util.newBuffer(object.revocationPoint);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.revokedAt = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.revokedAt = options.longs === String ? "0" : 0;
            }
            if (message.partyEnum != null && message.hasOwnProperty("partyEnum"))
                object.partyEnum = message.partyEnum;
            if (message.sequenceNumber != null && message.hasOwnProperty("sequenceNumber"))
                if (typeof message.sequenceNumber === "number")
                    object.sequenceNumber = options.longs === String ? String(message.sequenceNumber) : message.sequenceNumber;
                else
                    object.sequenceNumber = options.longs === String ? $util.Long.prototype.toString.call(message.sequenceNumber) : options.longs === Number ? new $util.LongBits(message.sequenceNumber.low >>> 0, message.sequenceNumber.high >>> 0).toNumber(true) : message.sequenceNumber;
            if (message.revocationSecret != null && message.hasOwnProperty("revocationSecret"))
                object.revocationSecret = options.bytes === String ? $util.base64.encode(message.revocationSecret, 0, message.revocationSecret.length) : options.bytes === Array ? Array.prototype.slice.call(message.revocationSecret) : message.revocationSecret;
            if (message.revocationPoint != null && message.hasOwnProperty("revocationPoint"))
                object.revocationPoint = options.bytes === String ? $util.base64.encode(message.revocationPoint, 0, message.revocationPoint.length) : options.bytes === Array ? Array.prototype.slice.call(message.revocationPoint) : message.revocationPoint;
            if (message.revokedAt != null && message.hasOwnProperty("revokedAt"))
                if (typeof message.revokedAt === "number")
                    object.revokedAt = options.longs === String ? String(message.revokedAt) : message.revokedAt;
                else
                    object.revokedAt = options.longs === String ? $util.Long.prototype.toString.call(message.revokedAt) : options.longs === Number ? new $util.LongBits(message.revokedAt.low >>> 0, message.revokedAt.high >>> 0).toNumber(true) : message.revokedAt;
            return object;
        };

        /**
         * Converts this RevocationData to JSON.
         * @function toJSON
         * @memberof p2p.RevocationData
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        RevocationData.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for RevocationData
         * @function getTypeUrl
         * @memberof p2p.RevocationData
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        RevocationData.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.RevocationData";
        };

        return RevocationData;
    })();

    p2p.PaymentProposal = (function() {

        /**
         * Properties of a PaymentProposal.
         * @memberof p2p
         * @interface IPaymentProposal
         * @property {Uint8Array|null} [channelId] PaymentProposal channelId
         * @property {number|Long|null} [newSequence] PaymentProposal newSequence
         * @property {number|Long|null} [amount] PaymentProposal amount
         * @property {number|null} [senderPartyEnum] PaymentProposal senderPartyEnum
         * @property {number|Long|null} [newBalanceA] PaymentProposal newBalanceA
         * @property {number|Long|null} [newBalanceB] PaymentProposal newBalanceB
         * @property {p2p.ICommitmentState|null} [newCommitment] PaymentProposal newCommitment
         * @property {p2p.IRevocationData|null} [oldRevocation] PaymentProposal oldRevocation
         * @property {number|Long|null} [timestamp] PaymentProposal timestamp
         */

        /**
         * Constructs a new PaymentProposal.
         * @memberof p2p
         * @classdesc Represents a PaymentProposal.
         * @implements IPaymentProposal
         * @constructor
         * @param {p2p.IPaymentProposal=} [properties] Properties to set
         */
        function PaymentProposal(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * PaymentProposal channelId.
         * @member {Uint8Array} channelId
         * @memberof p2p.PaymentProposal
         * @instance
         */
        PaymentProposal.prototype.channelId = $util.newBuffer([]);

        /**
         * PaymentProposal newSequence.
         * @member {number|Long} newSequence
         * @memberof p2p.PaymentProposal
         * @instance
         */
        PaymentProposal.prototype.newSequence = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * PaymentProposal amount.
         * @member {number|Long} amount
         * @memberof p2p.PaymentProposal
         * @instance
         */
        PaymentProposal.prototype.amount = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * PaymentProposal senderPartyEnum.
         * @member {number} senderPartyEnum
         * @memberof p2p.PaymentProposal
         * @instance
         */
        PaymentProposal.prototype.senderPartyEnum = 0;

        /**
         * PaymentProposal newBalanceA.
         * @member {number|Long} newBalanceA
         * @memberof p2p.PaymentProposal
         * @instance
         */
        PaymentProposal.prototype.newBalanceA = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * PaymentProposal newBalanceB.
         * @member {number|Long} newBalanceB
         * @memberof p2p.PaymentProposal
         * @instance
         */
        PaymentProposal.prototype.newBalanceB = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * PaymentProposal newCommitment.
         * @member {p2p.ICommitmentState|null|undefined} newCommitment
         * @memberof p2p.PaymentProposal
         * @instance
         */
        PaymentProposal.prototype.newCommitment = null;

        /**
         * PaymentProposal oldRevocation.
         * @member {p2p.IRevocationData|null|undefined} oldRevocation
         * @memberof p2p.PaymentProposal
         * @instance
         */
        PaymentProposal.prototype.oldRevocation = null;

        /**
         * PaymentProposal timestamp.
         * @member {number|Long} timestamp
         * @memberof p2p.PaymentProposal
         * @instance
         */
        PaymentProposal.prototype.timestamp = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        // OneOf field names bound to virtual getters and setters
        var $oneOfFields;

        /**
         * PaymentProposal _oldRevocation.
         * @member {"oldRevocation"|undefined} _oldRevocation
         * @memberof p2p.PaymentProposal
         * @instance
         */
        Object.defineProperty(PaymentProposal.prototype, "_oldRevocation", {
            get: $util.oneOfGetter($oneOfFields = ["oldRevocation"]),
            set: $util.oneOfSetter($oneOfFields)
        });

        /**
         * Creates a new PaymentProposal instance using the specified properties.
         * @function create
         * @memberof p2p.PaymentProposal
         * @static
         * @param {p2p.IPaymentProposal=} [properties] Properties to set
         * @returns {p2p.PaymentProposal} PaymentProposal instance
         */
        PaymentProposal.create = function create(properties) {
            return new PaymentProposal(properties);
        };

        /**
         * Encodes the specified PaymentProposal message. Does not implicitly {@link p2p.PaymentProposal.verify|verify} messages.
         * @function encode
         * @memberof p2p.PaymentProposal
         * @static
         * @param {p2p.IPaymentProposal} message PaymentProposal message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        PaymentProposal.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.channelId != null && Object.hasOwnProperty.call(message, "channelId"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.channelId);
            if (message.newSequence != null && Object.hasOwnProperty.call(message, "newSequence"))
                writer.uint32(/* id 2, wireType 0 =*/16).uint64(message.newSequence);
            if (message.amount != null && Object.hasOwnProperty.call(message, "amount"))
                writer.uint32(/* id 3, wireType 0 =*/24).uint64(message.amount);
            if (message.senderPartyEnum != null && Object.hasOwnProperty.call(message, "senderPartyEnum"))
                writer.uint32(/* id 4, wireType 0 =*/32).uint32(message.senderPartyEnum);
            if (message.newBalanceA != null && Object.hasOwnProperty.call(message, "newBalanceA"))
                writer.uint32(/* id 5, wireType 0 =*/40).uint64(message.newBalanceA);
            if (message.newBalanceB != null && Object.hasOwnProperty.call(message, "newBalanceB"))
                writer.uint32(/* id 6, wireType 0 =*/48).uint64(message.newBalanceB);
            if (message.newCommitment != null && Object.hasOwnProperty.call(message, "newCommitment"))
                $root.p2p.CommitmentState.encode(message.newCommitment, writer.uint32(/* id 7, wireType 2 =*/58).fork()).ldelim();
            if (message.oldRevocation != null && Object.hasOwnProperty.call(message, "oldRevocation"))
                $root.p2p.RevocationData.encode(message.oldRevocation, writer.uint32(/* id 8, wireType 2 =*/66).fork()).ldelim();
            if (message.timestamp != null && Object.hasOwnProperty.call(message, "timestamp"))
                writer.uint32(/* id 9, wireType 0 =*/72).uint64(message.timestamp);
            return writer;
        };

        /**
         * Encodes the specified PaymentProposal message, length delimited. Does not implicitly {@link p2p.PaymentProposal.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.PaymentProposal
         * @static
         * @param {p2p.IPaymentProposal} message PaymentProposal message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        PaymentProposal.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a PaymentProposal message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.PaymentProposal
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.PaymentProposal} PaymentProposal
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        PaymentProposal.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.PaymentProposal();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.channelId = reader.bytes();
                        break;
                    }
                case 2: {
                        message.newSequence = reader.uint64();
                        break;
                    }
                case 3: {
                        message.amount = reader.uint64();
                        break;
                    }
                case 4: {
                        message.senderPartyEnum = reader.uint32();
                        break;
                    }
                case 5: {
                        message.newBalanceA = reader.uint64();
                        break;
                    }
                case 6: {
                        message.newBalanceB = reader.uint64();
                        break;
                    }
                case 7: {
                        message.newCommitment = $root.p2p.CommitmentState.decode(reader, reader.uint32());
                        break;
                    }
                case 8: {
                        message.oldRevocation = $root.p2p.RevocationData.decode(reader, reader.uint32());
                        break;
                    }
                case 9: {
                        message.timestamp = reader.uint64();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a PaymentProposal message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.PaymentProposal
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.PaymentProposal} PaymentProposal
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        PaymentProposal.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a PaymentProposal message.
         * @function verify
         * @memberof p2p.PaymentProposal
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        PaymentProposal.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            var properties = {};
            if (message.channelId != null && message.hasOwnProperty("channelId"))
                if (!(message.channelId && typeof message.channelId.length === "number" || $util.isString(message.channelId)))
                    return "channelId: buffer expected";
            if (message.newSequence != null && message.hasOwnProperty("newSequence"))
                if (!$util.isInteger(message.newSequence) && !(message.newSequence && $util.isInteger(message.newSequence.low) && $util.isInteger(message.newSequence.high)))
                    return "newSequence: integer|Long expected";
            if (message.amount != null && message.hasOwnProperty("amount"))
                if (!$util.isInteger(message.amount) && !(message.amount && $util.isInteger(message.amount.low) && $util.isInteger(message.amount.high)))
                    return "amount: integer|Long expected";
            if (message.senderPartyEnum != null && message.hasOwnProperty("senderPartyEnum"))
                if (!$util.isInteger(message.senderPartyEnum))
                    return "senderPartyEnum: integer expected";
            if (message.newBalanceA != null && message.hasOwnProperty("newBalanceA"))
                if (!$util.isInteger(message.newBalanceA) && !(message.newBalanceA && $util.isInteger(message.newBalanceA.low) && $util.isInteger(message.newBalanceA.high)))
                    return "newBalanceA: integer|Long expected";
            if (message.newBalanceB != null && message.hasOwnProperty("newBalanceB"))
                if (!$util.isInteger(message.newBalanceB) && !(message.newBalanceB && $util.isInteger(message.newBalanceB.low) && $util.isInteger(message.newBalanceB.high)))
                    return "newBalanceB: integer|Long expected";
            if (message.newCommitment != null && message.hasOwnProperty("newCommitment")) {
                var error = $root.p2p.CommitmentState.verify(message.newCommitment);
                if (error)
                    return "newCommitment." + error;
            }
            if (message.oldRevocation != null && message.hasOwnProperty("oldRevocation")) {
                properties._oldRevocation = 1;
                {
                    var error = $root.p2p.RevocationData.verify(message.oldRevocation);
                    if (error)
                        return "oldRevocation." + error;
                }
            }
            if (message.timestamp != null && message.hasOwnProperty("timestamp"))
                if (!$util.isInteger(message.timestamp) && !(message.timestamp && $util.isInteger(message.timestamp.low) && $util.isInteger(message.timestamp.high)))
                    return "timestamp: integer|Long expected";
            return null;
        };

        /**
         * Creates a PaymentProposal message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.PaymentProposal
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.PaymentProposal} PaymentProposal
         */
        PaymentProposal.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.PaymentProposal)
                return object;
            var message = new $root.p2p.PaymentProposal();
            if (object.channelId != null)
                if (typeof object.channelId === "string")
                    $util.base64.decode(object.channelId, message.channelId = $util.newBuffer($util.base64.length(object.channelId)), 0);
                else if (object.channelId.length >= 0)
                    message.channelId = object.channelId;
            if (object.newSequence != null)
                if ($util.Long)
                    (message.newSequence = $util.Long.fromValue(object.newSequence)).unsigned = true;
                else if (typeof object.newSequence === "string")
                    message.newSequence = parseInt(object.newSequence, 10);
                else if (typeof object.newSequence === "number")
                    message.newSequence = object.newSequence;
                else if (typeof object.newSequence === "object")
                    message.newSequence = new $util.LongBits(object.newSequence.low >>> 0, object.newSequence.high >>> 0).toNumber(true);
            if (object.amount != null)
                if ($util.Long)
                    (message.amount = $util.Long.fromValue(object.amount)).unsigned = true;
                else if (typeof object.amount === "string")
                    message.amount = parseInt(object.amount, 10);
                else if (typeof object.amount === "number")
                    message.amount = object.amount;
                else if (typeof object.amount === "object")
                    message.amount = new $util.LongBits(object.amount.low >>> 0, object.amount.high >>> 0).toNumber(true);
            if (object.senderPartyEnum != null)
                message.senderPartyEnum = object.senderPartyEnum >>> 0;
            if (object.newBalanceA != null)
                if ($util.Long)
                    (message.newBalanceA = $util.Long.fromValue(object.newBalanceA)).unsigned = true;
                else if (typeof object.newBalanceA === "string")
                    message.newBalanceA = parseInt(object.newBalanceA, 10);
                else if (typeof object.newBalanceA === "number")
                    message.newBalanceA = object.newBalanceA;
                else if (typeof object.newBalanceA === "object")
                    message.newBalanceA = new $util.LongBits(object.newBalanceA.low >>> 0, object.newBalanceA.high >>> 0).toNumber(true);
            if (object.newBalanceB != null)
                if ($util.Long)
                    (message.newBalanceB = $util.Long.fromValue(object.newBalanceB)).unsigned = true;
                else if (typeof object.newBalanceB === "string")
                    message.newBalanceB = parseInt(object.newBalanceB, 10);
                else if (typeof object.newBalanceB === "number")
                    message.newBalanceB = object.newBalanceB;
                else if (typeof object.newBalanceB === "object")
                    message.newBalanceB = new $util.LongBits(object.newBalanceB.low >>> 0, object.newBalanceB.high >>> 0).toNumber(true);
            if (object.newCommitment != null) {
                if (typeof object.newCommitment !== "object")
                    throw TypeError(".p2p.PaymentProposal.newCommitment: object expected");
                message.newCommitment = $root.p2p.CommitmentState.fromObject(object.newCommitment);
            }
            if (object.oldRevocation != null) {
                if (typeof object.oldRevocation !== "object")
                    throw TypeError(".p2p.PaymentProposal.oldRevocation: object expected");
                message.oldRevocation = $root.p2p.RevocationData.fromObject(object.oldRevocation);
            }
            if (object.timestamp != null)
                if ($util.Long)
                    (message.timestamp = $util.Long.fromValue(object.timestamp)).unsigned = true;
                else if (typeof object.timestamp === "string")
                    message.timestamp = parseInt(object.timestamp, 10);
                else if (typeof object.timestamp === "number")
                    message.timestamp = object.timestamp;
                else if (typeof object.timestamp === "object")
                    message.timestamp = new $util.LongBits(object.timestamp.low >>> 0, object.timestamp.high >>> 0).toNumber(true);
            return message;
        };

        /**
         * Creates a plain object from a PaymentProposal message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.PaymentProposal
         * @static
         * @param {p2p.PaymentProposal} message PaymentProposal
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        PaymentProposal.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.channelId = "";
                else {
                    object.channelId = [];
                    if (options.bytes !== Array)
                        object.channelId = $util.newBuffer(object.channelId);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.newSequence = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.newSequence = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.amount = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.amount = options.longs === String ? "0" : 0;
                object.senderPartyEnum = 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.newBalanceA = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.newBalanceA = options.longs === String ? "0" : 0;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.newBalanceB = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.newBalanceB = options.longs === String ? "0" : 0;
                object.newCommitment = null;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.timestamp = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.timestamp = options.longs === String ? "0" : 0;
            }
            if (message.channelId != null && message.hasOwnProperty("channelId"))
                object.channelId = options.bytes === String ? $util.base64.encode(message.channelId, 0, message.channelId.length) : options.bytes === Array ? Array.prototype.slice.call(message.channelId) : message.channelId;
            if (message.newSequence != null && message.hasOwnProperty("newSequence"))
                if (typeof message.newSequence === "number")
                    object.newSequence = options.longs === String ? String(message.newSequence) : message.newSequence;
                else
                    object.newSequence = options.longs === String ? $util.Long.prototype.toString.call(message.newSequence) : options.longs === Number ? new $util.LongBits(message.newSequence.low >>> 0, message.newSequence.high >>> 0).toNumber(true) : message.newSequence;
            if (message.amount != null && message.hasOwnProperty("amount"))
                if (typeof message.amount === "number")
                    object.amount = options.longs === String ? String(message.amount) : message.amount;
                else
                    object.amount = options.longs === String ? $util.Long.prototype.toString.call(message.amount) : options.longs === Number ? new $util.LongBits(message.amount.low >>> 0, message.amount.high >>> 0).toNumber(true) : message.amount;
            if (message.senderPartyEnum != null && message.hasOwnProperty("senderPartyEnum"))
                object.senderPartyEnum = message.senderPartyEnum;
            if (message.newBalanceA != null && message.hasOwnProperty("newBalanceA"))
                if (typeof message.newBalanceA === "number")
                    object.newBalanceA = options.longs === String ? String(message.newBalanceA) : message.newBalanceA;
                else
                    object.newBalanceA = options.longs === String ? $util.Long.prototype.toString.call(message.newBalanceA) : options.longs === Number ? new $util.LongBits(message.newBalanceA.low >>> 0, message.newBalanceA.high >>> 0).toNumber(true) : message.newBalanceA;
            if (message.newBalanceB != null && message.hasOwnProperty("newBalanceB"))
                if (typeof message.newBalanceB === "number")
                    object.newBalanceB = options.longs === String ? String(message.newBalanceB) : message.newBalanceB;
                else
                    object.newBalanceB = options.longs === String ? $util.Long.prototype.toString.call(message.newBalanceB) : options.longs === Number ? new $util.LongBits(message.newBalanceB.low >>> 0, message.newBalanceB.high >>> 0).toNumber(true) : message.newBalanceB;
            if (message.newCommitment != null && message.hasOwnProperty("newCommitment"))
                object.newCommitment = $root.p2p.CommitmentState.toObject(message.newCommitment, options);
            if (message.oldRevocation != null && message.hasOwnProperty("oldRevocation")) {
                object.oldRevocation = $root.p2p.RevocationData.toObject(message.oldRevocation, options);
                if (options.oneofs)
                    object._oldRevocation = "oldRevocation";
            }
            if (message.timestamp != null && message.hasOwnProperty("timestamp"))
                if (typeof message.timestamp === "number")
                    object.timestamp = options.longs === String ? String(message.timestamp) : message.timestamp;
                else
                    object.timestamp = options.longs === String ? $util.Long.prototype.toString.call(message.timestamp) : options.longs === Number ? new $util.LongBits(message.timestamp.low >>> 0, message.timestamp.high >>> 0).toNumber(true) : message.timestamp;
            return object;
        };

        /**
         * Converts this PaymentProposal to JSON.
         * @function toJSON
         * @memberof p2p.PaymentProposal
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        PaymentProposal.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for PaymentProposal
         * @function getTypeUrl
         * @memberof p2p.PaymentProposal
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        PaymentProposal.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.PaymentProposal";
        };

        return PaymentProposal;
    })();

    p2p.PaymentAcceptance = (function() {

        /**
         * Properties of a PaymentAcceptance.
         * @memberof p2p
         * @interface IPaymentAcceptance
         * @property {Uint8Array|null} [channelId] PaymentAcceptance channelId
         * @property {number|Long|null} [sequence] PaymentAcceptance sequence
         * @property {p2p.ICommitmentState|null} [newCommitment] PaymentAcceptance newCommitment
         * @property {p2p.IRevocationData|null} [oldRevocation] PaymentAcceptance oldRevocation
         * @property {number|Long|null} [acceptedAt] PaymentAcceptance acceptedAt
         */

        /**
         * Constructs a new PaymentAcceptance.
         * @memberof p2p
         * @classdesc Represents a PaymentAcceptance.
         * @implements IPaymentAcceptance
         * @constructor
         * @param {p2p.IPaymentAcceptance=} [properties] Properties to set
         */
        function PaymentAcceptance(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * PaymentAcceptance channelId.
         * @member {Uint8Array} channelId
         * @memberof p2p.PaymentAcceptance
         * @instance
         */
        PaymentAcceptance.prototype.channelId = $util.newBuffer([]);

        /**
         * PaymentAcceptance sequence.
         * @member {number|Long} sequence
         * @memberof p2p.PaymentAcceptance
         * @instance
         */
        PaymentAcceptance.prototype.sequence = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * PaymentAcceptance newCommitment.
         * @member {p2p.ICommitmentState|null|undefined} newCommitment
         * @memberof p2p.PaymentAcceptance
         * @instance
         */
        PaymentAcceptance.prototype.newCommitment = null;

        /**
         * PaymentAcceptance oldRevocation.
         * @member {p2p.IRevocationData|null|undefined} oldRevocation
         * @memberof p2p.PaymentAcceptance
         * @instance
         */
        PaymentAcceptance.prototype.oldRevocation = null;

        /**
         * PaymentAcceptance acceptedAt.
         * @member {number|Long} acceptedAt
         * @memberof p2p.PaymentAcceptance
         * @instance
         */
        PaymentAcceptance.prototype.acceptedAt = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        // OneOf field names bound to virtual getters and setters
        var $oneOfFields;

        /**
         * PaymentAcceptance _oldRevocation.
         * @member {"oldRevocation"|undefined} _oldRevocation
         * @memberof p2p.PaymentAcceptance
         * @instance
         */
        Object.defineProperty(PaymentAcceptance.prototype, "_oldRevocation", {
            get: $util.oneOfGetter($oneOfFields = ["oldRevocation"]),
            set: $util.oneOfSetter($oneOfFields)
        });

        /**
         * Creates a new PaymentAcceptance instance using the specified properties.
         * @function create
         * @memberof p2p.PaymentAcceptance
         * @static
         * @param {p2p.IPaymentAcceptance=} [properties] Properties to set
         * @returns {p2p.PaymentAcceptance} PaymentAcceptance instance
         */
        PaymentAcceptance.create = function create(properties) {
            return new PaymentAcceptance(properties);
        };

        /**
         * Encodes the specified PaymentAcceptance message. Does not implicitly {@link p2p.PaymentAcceptance.verify|verify} messages.
         * @function encode
         * @memberof p2p.PaymentAcceptance
         * @static
         * @param {p2p.IPaymentAcceptance} message PaymentAcceptance message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        PaymentAcceptance.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.channelId != null && Object.hasOwnProperty.call(message, "channelId"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.channelId);
            if (message.sequence != null && Object.hasOwnProperty.call(message, "sequence"))
                writer.uint32(/* id 2, wireType 0 =*/16).uint64(message.sequence);
            if (message.newCommitment != null && Object.hasOwnProperty.call(message, "newCommitment"))
                $root.p2p.CommitmentState.encode(message.newCommitment, writer.uint32(/* id 3, wireType 2 =*/26).fork()).ldelim();
            if (message.oldRevocation != null && Object.hasOwnProperty.call(message, "oldRevocation"))
                $root.p2p.RevocationData.encode(message.oldRevocation, writer.uint32(/* id 4, wireType 2 =*/34).fork()).ldelim();
            if (message.acceptedAt != null && Object.hasOwnProperty.call(message, "acceptedAt"))
                writer.uint32(/* id 5, wireType 0 =*/40).uint64(message.acceptedAt);
            return writer;
        };

        /**
         * Encodes the specified PaymentAcceptance message, length delimited. Does not implicitly {@link p2p.PaymentAcceptance.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.PaymentAcceptance
         * @static
         * @param {p2p.IPaymentAcceptance} message PaymentAcceptance message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        PaymentAcceptance.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a PaymentAcceptance message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.PaymentAcceptance
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.PaymentAcceptance} PaymentAcceptance
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        PaymentAcceptance.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.PaymentAcceptance();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.channelId = reader.bytes();
                        break;
                    }
                case 2: {
                        message.sequence = reader.uint64();
                        break;
                    }
                case 3: {
                        message.newCommitment = $root.p2p.CommitmentState.decode(reader, reader.uint32());
                        break;
                    }
                case 4: {
                        message.oldRevocation = $root.p2p.RevocationData.decode(reader, reader.uint32());
                        break;
                    }
                case 5: {
                        message.acceptedAt = reader.uint64();
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a PaymentAcceptance message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.PaymentAcceptance
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.PaymentAcceptance} PaymentAcceptance
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        PaymentAcceptance.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a PaymentAcceptance message.
         * @function verify
         * @memberof p2p.PaymentAcceptance
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        PaymentAcceptance.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            var properties = {};
            if (message.channelId != null && message.hasOwnProperty("channelId"))
                if (!(message.channelId && typeof message.channelId.length === "number" || $util.isString(message.channelId)))
                    return "channelId: buffer expected";
            if (message.sequence != null && message.hasOwnProperty("sequence"))
                if (!$util.isInteger(message.sequence) && !(message.sequence && $util.isInteger(message.sequence.low) && $util.isInteger(message.sequence.high)))
                    return "sequence: integer|Long expected";
            if (message.newCommitment != null && message.hasOwnProperty("newCommitment")) {
                var error = $root.p2p.CommitmentState.verify(message.newCommitment);
                if (error)
                    return "newCommitment." + error;
            }
            if (message.oldRevocation != null && message.hasOwnProperty("oldRevocation")) {
                properties._oldRevocation = 1;
                {
                    var error = $root.p2p.RevocationData.verify(message.oldRevocation);
                    if (error)
                        return "oldRevocation." + error;
                }
            }
            if (message.acceptedAt != null && message.hasOwnProperty("acceptedAt"))
                if (!$util.isInteger(message.acceptedAt) && !(message.acceptedAt && $util.isInteger(message.acceptedAt.low) && $util.isInteger(message.acceptedAt.high)))
                    return "acceptedAt: integer|Long expected";
            return null;
        };

        /**
         * Creates a PaymentAcceptance message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.PaymentAcceptance
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.PaymentAcceptance} PaymentAcceptance
         */
        PaymentAcceptance.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.PaymentAcceptance)
                return object;
            var message = new $root.p2p.PaymentAcceptance();
            if (object.channelId != null)
                if (typeof object.channelId === "string")
                    $util.base64.decode(object.channelId, message.channelId = $util.newBuffer($util.base64.length(object.channelId)), 0);
                else if (object.channelId.length >= 0)
                    message.channelId = object.channelId;
            if (object.sequence != null)
                if ($util.Long)
                    (message.sequence = $util.Long.fromValue(object.sequence)).unsigned = true;
                else if (typeof object.sequence === "string")
                    message.sequence = parseInt(object.sequence, 10);
                else if (typeof object.sequence === "number")
                    message.sequence = object.sequence;
                else if (typeof object.sequence === "object")
                    message.sequence = new $util.LongBits(object.sequence.low >>> 0, object.sequence.high >>> 0).toNumber(true);
            if (object.newCommitment != null) {
                if (typeof object.newCommitment !== "object")
                    throw TypeError(".p2p.PaymentAcceptance.newCommitment: object expected");
                message.newCommitment = $root.p2p.CommitmentState.fromObject(object.newCommitment);
            }
            if (object.oldRevocation != null) {
                if (typeof object.oldRevocation !== "object")
                    throw TypeError(".p2p.PaymentAcceptance.oldRevocation: object expected");
                message.oldRevocation = $root.p2p.RevocationData.fromObject(object.oldRevocation);
            }
            if (object.acceptedAt != null)
                if ($util.Long)
                    (message.acceptedAt = $util.Long.fromValue(object.acceptedAt)).unsigned = true;
                else if (typeof object.acceptedAt === "string")
                    message.acceptedAt = parseInt(object.acceptedAt, 10);
                else if (typeof object.acceptedAt === "number")
                    message.acceptedAt = object.acceptedAt;
                else if (typeof object.acceptedAt === "object")
                    message.acceptedAt = new $util.LongBits(object.acceptedAt.low >>> 0, object.acceptedAt.high >>> 0).toNumber(true);
            return message;
        };

        /**
         * Creates a plain object from a PaymentAcceptance message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.PaymentAcceptance
         * @static
         * @param {p2p.PaymentAcceptance} message PaymentAcceptance
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        PaymentAcceptance.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (options.defaults) {
                if (options.bytes === String)
                    object.channelId = "";
                else {
                    object.channelId = [];
                    if (options.bytes !== Array)
                        object.channelId = $util.newBuffer(object.channelId);
                }
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.sequence = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.sequence = options.longs === String ? "0" : 0;
                object.newCommitment = null;
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.acceptedAt = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.acceptedAt = options.longs === String ? "0" : 0;
            }
            if (message.channelId != null && message.hasOwnProperty("channelId"))
                object.channelId = options.bytes === String ? $util.base64.encode(message.channelId, 0, message.channelId.length) : options.bytes === Array ? Array.prototype.slice.call(message.channelId) : message.channelId;
            if (message.sequence != null && message.hasOwnProperty("sequence"))
                if (typeof message.sequence === "number")
                    object.sequence = options.longs === String ? String(message.sequence) : message.sequence;
                else
                    object.sequence = options.longs === String ? $util.Long.prototype.toString.call(message.sequence) : options.longs === Number ? new $util.LongBits(message.sequence.low >>> 0, message.sequence.high >>> 0).toNumber(true) : message.sequence;
            if (message.newCommitment != null && message.hasOwnProperty("newCommitment"))
                object.newCommitment = $root.p2p.CommitmentState.toObject(message.newCommitment, options);
            if (message.oldRevocation != null && message.hasOwnProperty("oldRevocation")) {
                object.oldRevocation = $root.p2p.RevocationData.toObject(message.oldRevocation, options);
                if (options.oneofs)
                    object._oldRevocation = "oldRevocation";
            }
            if (message.acceptedAt != null && message.hasOwnProperty("acceptedAt"))
                if (typeof message.acceptedAt === "number")
                    object.acceptedAt = options.longs === String ? String(message.acceptedAt) : message.acceptedAt;
                else
                    object.acceptedAt = options.longs === String ? $util.Long.prototype.toString.call(message.acceptedAt) : options.longs === Number ? new $util.LongBits(message.acceptedAt.low >>> 0, message.acceptedAt.high >>> 0).toNumber(true) : message.acceptedAt;
            return object;
        };

        /**
         * Converts this PaymentAcceptance to JSON.
         * @function toJSON
         * @memberof p2p.PaymentAcceptance
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        PaymentAcceptance.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for PaymentAcceptance
         * @function getTypeUrl
         * @memberof p2p.PaymentAcceptance
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        PaymentAcceptance.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.PaymentAcceptance";
        };

        return PaymentAcceptance;
    })();

    p2p.P2pMessage = (function() {

        /**
         * Properties of a P2pMessage.
         * @memberof p2p
         * @interface IP2pMessage
         * @property {p2p.IBlock|null} [block] P2pMessage block
         * @property {p2p.ITransaction|null} [transaction] P2pMessage transaction
         * @property {p2p.IBlockAnnouncement|null} [blockAnnouncement] P2pMessage blockAnnouncement
         * @property {p2p.IBlockRequest|null} [blockRequest] P2pMessage blockRequest
         * @property {p2p.IGetHashesRequest|null} [getHashesRequest] P2pMessage getHashesRequest
         * @property {p2p.IHashesResponse|null} [hashesResponse] P2pMessage hashesResponse
         * @property {p2p.ISyncMessage|null} [syncMessage] P2pMessage syncMessage
         * @property {p2p.IDandelionStem|null} [dandelionStem] P2pMessage dandelionStem
         * @property {p2p.IAtomicSwap|null} [swapPropose] P2pMessage swapPropose
         * @property {p2p.IAtomicSwap|null} [swapRespond] P2pMessage swapRespond
         * @property {p2p.ISwapAliceAdaptorSig|null} [swapAliceAdaptorSig] P2pMessage swapAliceAdaptorSig
         * @property {p2p.IChannelProposal|null} [channelPropose] P2pMessage channelPropose
         * @property {p2p.IChannelAcceptance|null} [channelAccept] P2pMessage channelAccept
         * @property {p2p.IChannelNonce|null} [channelFundNonce] P2pMessage channelFundNonce
         * @property {p2p.IChannelPartialSig|null} [channelFundSig] P2pMessage channelFundSig
         * @property {p2p.IPaymentProposal|null} [channelPayPropose] P2pMessage channelPayPropose
         * @property {p2p.IPaymentAcceptance|null} [channelPayAccept] P2pMessage channelPayAccept
         * @property {p2p.IChannelNonce|null} [channelCloseNonce] P2pMessage channelCloseNonce
         * @property {p2p.IChannelPartialSig|null} [channelCloseSig] P2pMessage channelCloseSig
         */

        /**
         * Constructs a new P2pMessage.
         * @memberof p2p
         * @classdesc Represents a P2pMessage.
         * @implements IP2pMessage
         * @constructor
         * @param {p2p.IP2pMessage=} [properties] Properties to set
         */
        function P2pMessage(properties) {
            if (properties)
                for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null)
                        this[keys[i]] = properties[keys[i]];
        }

        /**
         * P2pMessage block.
         * @member {p2p.IBlock|null|undefined} block
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.block = null;

        /**
         * P2pMessage transaction.
         * @member {p2p.ITransaction|null|undefined} transaction
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.transaction = null;

        /**
         * P2pMessage blockAnnouncement.
         * @member {p2p.IBlockAnnouncement|null|undefined} blockAnnouncement
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.blockAnnouncement = null;

        /**
         * P2pMessage blockRequest.
         * @member {p2p.IBlockRequest|null|undefined} blockRequest
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.blockRequest = null;

        /**
         * P2pMessage getHashesRequest.
         * @member {p2p.IGetHashesRequest|null|undefined} getHashesRequest
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.getHashesRequest = null;

        /**
         * P2pMessage hashesResponse.
         * @member {p2p.IHashesResponse|null|undefined} hashesResponse
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.hashesResponse = null;

        /**
         * P2pMessage syncMessage.
         * @member {p2p.ISyncMessage|null|undefined} syncMessage
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.syncMessage = null;

        /**
         * P2pMessage dandelionStem.
         * @member {p2p.IDandelionStem|null|undefined} dandelionStem
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.dandelionStem = null;

        /**
         * P2pMessage swapPropose.
         * @member {p2p.IAtomicSwap|null|undefined} swapPropose
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.swapPropose = null;

        /**
         * P2pMessage swapRespond.
         * @member {p2p.IAtomicSwap|null|undefined} swapRespond
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.swapRespond = null;

        /**
         * P2pMessage swapAliceAdaptorSig.
         * @member {p2p.ISwapAliceAdaptorSig|null|undefined} swapAliceAdaptorSig
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.swapAliceAdaptorSig = null;

        /**
         * P2pMessage channelPropose.
         * @member {p2p.IChannelProposal|null|undefined} channelPropose
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.channelPropose = null;

        /**
         * P2pMessage channelAccept.
         * @member {p2p.IChannelAcceptance|null|undefined} channelAccept
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.channelAccept = null;

        /**
         * P2pMessage channelFundNonce.
         * @member {p2p.IChannelNonce|null|undefined} channelFundNonce
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.channelFundNonce = null;

        /**
         * P2pMessage channelFundSig.
         * @member {p2p.IChannelPartialSig|null|undefined} channelFundSig
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.channelFundSig = null;

        /**
         * P2pMessage channelPayPropose.
         * @member {p2p.IPaymentProposal|null|undefined} channelPayPropose
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.channelPayPropose = null;

        /**
         * P2pMessage channelPayAccept.
         * @member {p2p.IPaymentAcceptance|null|undefined} channelPayAccept
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.channelPayAccept = null;

        /**
         * P2pMessage channelCloseNonce.
         * @member {p2p.IChannelNonce|null|undefined} channelCloseNonce
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.channelCloseNonce = null;

        /**
         * P2pMessage channelCloseSig.
         * @member {p2p.IChannelPartialSig|null|undefined} channelCloseSig
         * @memberof p2p.P2pMessage
         * @instance
         */
        P2pMessage.prototype.channelCloseSig = null;

        // OneOf field names bound to virtual getters and setters
        var $oneOfFields;

        /**
         * P2pMessage payload.
         * @member {"block"|"transaction"|"blockAnnouncement"|"blockRequest"|"getHashesRequest"|"hashesResponse"|"syncMessage"|"dandelionStem"|"swapPropose"|"swapRespond"|"swapAliceAdaptorSig"|"channelPropose"|"channelAccept"|"channelFundNonce"|"channelFundSig"|"channelPayPropose"|"channelPayAccept"|"channelCloseNonce"|"channelCloseSig"|undefined} payload
         * @memberof p2p.P2pMessage
         * @instance
         */
        Object.defineProperty(P2pMessage.prototype, "payload", {
            get: $util.oneOfGetter($oneOfFields = ["block", "transaction", "blockAnnouncement", "blockRequest", "getHashesRequest", "hashesResponse", "syncMessage", "dandelionStem", "swapPropose", "swapRespond", "swapAliceAdaptorSig", "channelPropose", "channelAccept", "channelFundNonce", "channelFundSig", "channelPayPropose", "channelPayAccept", "channelCloseNonce", "channelCloseSig"]),
            set: $util.oneOfSetter($oneOfFields)
        });

        /**
         * Creates a new P2pMessage instance using the specified properties.
         * @function create
         * @memberof p2p.P2pMessage
         * @static
         * @param {p2p.IP2pMessage=} [properties] Properties to set
         * @returns {p2p.P2pMessage} P2pMessage instance
         */
        P2pMessage.create = function create(properties) {
            return new P2pMessage(properties);
        };

        /**
         * Encodes the specified P2pMessage message. Does not implicitly {@link p2p.P2pMessage.verify|verify} messages.
         * @function encode
         * @memberof p2p.P2pMessage
         * @static
         * @param {p2p.IP2pMessage} message P2pMessage message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        P2pMessage.encode = function encode(message, writer) {
            if (!writer)
                writer = $Writer.create();
            if (message.block != null && Object.hasOwnProperty.call(message, "block"))
                $root.p2p.Block.encode(message.block, writer.uint32(/* id 1, wireType 2 =*/10).fork()).ldelim();
            if (message.transaction != null && Object.hasOwnProperty.call(message, "transaction"))
                $root.p2p.Transaction.encode(message.transaction, writer.uint32(/* id 2, wireType 2 =*/18).fork()).ldelim();
            if (message.blockAnnouncement != null && Object.hasOwnProperty.call(message, "blockAnnouncement"))
                $root.p2p.BlockAnnouncement.encode(message.blockAnnouncement, writer.uint32(/* id 3, wireType 2 =*/26).fork()).ldelim();
            if (message.blockRequest != null && Object.hasOwnProperty.call(message, "blockRequest"))
                $root.p2p.BlockRequest.encode(message.blockRequest, writer.uint32(/* id 4, wireType 2 =*/34).fork()).ldelim();
            if (message.getHashesRequest != null && Object.hasOwnProperty.call(message, "getHashesRequest"))
                $root.p2p.GetHashesRequest.encode(message.getHashesRequest, writer.uint32(/* id 5, wireType 2 =*/42).fork()).ldelim();
            if (message.hashesResponse != null && Object.hasOwnProperty.call(message, "hashesResponse"))
                $root.p2p.HashesResponse.encode(message.hashesResponse, writer.uint32(/* id 6, wireType 2 =*/50).fork()).ldelim();
            if (message.syncMessage != null && Object.hasOwnProperty.call(message, "syncMessage"))
                $root.p2p.SyncMessage.encode(message.syncMessage, writer.uint32(/* id 7, wireType 2 =*/58).fork()).ldelim();
            if (message.dandelionStem != null && Object.hasOwnProperty.call(message, "dandelionStem"))
                $root.p2p.DandelionStem.encode(message.dandelionStem, writer.uint32(/* id 8, wireType 2 =*/66).fork()).ldelim();
            if (message.swapPropose != null && Object.hasOwnProperty.call(message, "swapPropose"))
                $root.p2p.AtomicSwap.encode(message.swapPropose, writer.uint32(/* id 9, wireType 2 =*/74).fork()).ldelim();
            if (message.swapRespond != null && Object.hasOwnProperty.call(message, "swapRespond"))
                $root.p2p.AtomicSwap.encode(message.swapRespond, writer.uint32(/* id 10, wireType 2 =*/82).fork()).ldelim();
            if (message.swapAliceAdaptorSig != null && Object.hasOwnProperty.call(message, "swapAliceAdaptorSig"))
                $root.p2p.SwapAliceAdaptorSig.encode(message.swapAliceAdaptorSig, writer.uint32(/* id 11, wireType 2 =*/90).fork()).ldelim();
            if (message.channelPropose != null && Object.hasOwnProperty.call(message, "channelPropose"))
                $root.p2p.ChannelProposal.encode(message.channelPropose, writer.uint32(/* id 12, wireType 2 =*/98).fork()).ldelim();
            if (message.channelAccept != null && Object.hasOwnProperty.call(message, "channelAccept"))
                $root.p2p.ChannelAcceptance.encode(message.channelAccept, writer.uint32(/* id 13, wireType 2 =*/106).fork()).ldelim();
            if (message.channelFundNonce != null && Object.hasOwnProperty.call(message, "channelFundNonce"))
                $root.p2p.ChannelNonce.encode(message.channelFundNonce, writer.uint32(/* id 14, wireType 2 =*/114).fork()).ldelim();
            if (message.channelFundSig != null && Object.hasOwnProperty.call(message, "channelFundSig"))
                $root.p2p.ChannelPartialSig.encode(message.channelFundSig, writer.uint32(/* id 15, wireType 2 =*/122).fork()).ldelim();
            if (message.channelPayPropose != null && Object.hasOwnProperty.call(message, "channelPayPropose"))
                $root.p2p.PaymentProposal.encode(message.channelPayPropose, writer.uint32(/* id 16, wireType 2 =*/130).fork()).ldelim();
            if (message.channelPayAccept != null && Object.hasOwnProperty.call(message, "channelPayAccept"))
                $root.p2p.PaymentAcceptance.encode(message.channelPayAccept, writer.uint32(/* id 17, wireType 2 =*/138).fork()).ldelim();
            if (message.channelCloseNonce != null && Object.hasOwnProperty.call(message, "channelCloseNonce"))
                $root.p2p.ChannelNonce.encode(message.channelCloseNonce, writer.uint32(/* id 18, wireType 2 =*/146).fork()).ldelim();
            if (message.channelCloseSig != null && Object.hasOwnProperty.call(message, "channelCloseSig"))
                $root.p2p.ChannelPartialSig.encode(message.channelCloseSig, writer.uint32(/* id 19, wireType 2 =*/154).fork()).ldelim();
            return writer;
        };

        /**
         * Encodes the specified P2pMessage message, length delimited. Does not implicitly {@link p2p.P2pMessage.verify|verify} messages.
         * @function encodeDelimited
         * @memberof p2p.P2pMessage
         * @static
         * @param {p2p.IP2pMessage} message P2pMessage message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        P2pMessage.encodeDelimited = function encodeDelimited(message, writer) {
            return this.encode(message, writer).ldelim();
        };

        /**
         * Decodes a P2pMessage message from the specified reader or buffer.
         * @function decode
         * @memberof p2p.P2pMessage
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {p2p.P2pMessage} P2pMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        P2pMessage.decode = function decode(reader, length, error) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            var end = length === undefined ? reader.len : reader.pos + length, message = new $root.p2p.P2pMessage();
            while (reader.pos < end) {
                var tag = reader.uint32();
                if (tag === error)
                    break;
                switch (tag >>> 3) {
                case 1: {
                        message.block = $root.p2p.Block.decode(reader, reader.uint32());
                        break;
                    }
                case 2: {
                        message.transaction = $root.p2p.Transaction.decode(reader, reader.uint32());
                        break;
                    }
                case 3: {
                        message.blockAnnouncement = $root.p2p.BlockAnnouncement.decode(reader, reader.uint32());
                        break;
                    }
                case 4: {
                        message.blockRequest = $root.p2p.BlockRequest.decode(reader, reader.uint32());
                        break;
                    }
                case 5: {
                        message.getHashesRequest = $root.p2p.GetHashesRequest.decode(reader, reader.uint32());
                        break;
                    }
                case 6: {
                        message.hashesResponse = $root.p2p.HashesResponse.decode(reader, reader.uint32());
                        break;
                    }
                case 7: {
                        message.syncMessage = $root.p2p.SyncMessage.decode(reader, reader.uint32());
                        break;
                    }
                case 8: {
                        message.dandelionStem = $root.p2p.DandelionStem.decode(reader, reader.uint32());
                        break;
                    }
                case 9: {
                        message.swapPropose = $root.p2p.AtomicSwap.decode(reader, reader.uint32());
                        break;
                    }
                case 10: {
                        message.swapRespond = $root.p2p.AtomicSwap.decode(reader, reader.uint32());
                        break;
                    }
                case 11: {
                        message.swapAliceAdaptorSig = $root.p2p.SwapAliceAdaptorSig.decode(reader, reader.uint32());
                        break;
                    }
                case 12: {
                        message.channelPropose = $root.p2p.ChannelProposal.decode(reader, reader.uint32());
                        break;
                    }
                case 13: {
                        message.channelAccept = $root.p2p.ChannelAcceptance.decode(reader, reader.uint32());
                        break;
                    }
                case 14: {
                        message.channelFundNonce = $root.p2p.ChannelNonce.decode(reader, reader.uint32());
                        break;
                    }
                case 15: {
                        message.channelFundSig = $root.p2p.ChannelPartialSig.decode(reader, reader.uint32());
                        break;
                    }
                case 16: {
                        message.channelPayPropose = $root.p2p.PaymentProposal.decode(reader, reader.uint32());
                        break;
                    }
                case 17: {
                        message.channelPayAccept = $root.p2p.PaymentAcceptance.decode(reader, reader.uint32());
                        break;
                    }
                case 18: {
                        message.channelCloseNonce = $root.p2p.ChannelNonce.decode(reader, reader.uint32());
                        break;
                    }
                case 19: {
                        message.channelCloseSig = $root.p2p.ChannelPartialSig.decode(reader, reader.uint32());
                        break;
                    }
                default:
                    reader.skipType(tag & 7);
                    break;
                }
            }
            return message;
        };

        /**
         * Decodes a P2pMessage message from the specified reader or buffer, length delimited.
         * @function decodeDelimited
         * @memberof p2p.P2pMessage
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @returns {p2p.P2pMessage} P2pMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        P2pMessage.decodeDelimited = function decodeDelimited(reader) {
            if (!(reader instanceof $Reader))
                reader = new $Reader(reader);
            return this.decode(reader, reader.uint32());
        };

        /**
         * Verifies a P2pMessage message.
         * @function verify
         * @memberof p2p.P2pMessage
         * @static
         * @param {Object.<string,*>} message Plain object to verify
         * @returns {string|null} `null` if valid, otherwise the reason why it is not
         */
        P2pMessage.verify = function verify(message) {
            if (typeof message !== "object" || message === null)
                return "object expected";
            var properties = {};
            if (message.block != null && message.hasOwnProperty("block")) {
                properties.payload = 1;
                {
                    var error = $root.p2p.Block.verify(message.block);
                    if (error)
                        return "block." + error;
                }
            }
            if (message.transaction != null && message.hasOwnProperty("transaction")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.Transaction.verify(message.transaction);
                    if (error)
                        return "transaction." + error;
                }
            }
            if (message.blockAnnouncement != null && message.hasOwnProperty("blockAnnouncement")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.BlockAnnouncement.verify(message.blockAnnouncement);
                    if (error)
                        return "blockAnnouncement." + error;
                }
            }
            if (message.blockRequest != null && message.hasOwnProperty("blockRequest")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.BlockRequest.verify(message.blockRequest);
                    if (error)
                        return "blockRequest." + error;
                }
            }
            if (message.getHashesRequest != null && message.hasOwnProperty("getHashesRequest")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.GetHashesRequest.verify(message.getHashesRequest);
                    if (error)
                        return "getHashesRequest." + error;
                }
            }
            if (message.hashesResponse != null && message.hasOwnProperty("hashesResponse")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.HashesResponse.verify(message.hashesResponse);
                    if (error)
                        return "hashesResponse." + error;
                }
            }
            if (message.syncMessage != null && message.hasOwnProperty("syncMessage")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.SyncMessage.verify(message.syncMessage);
                    if (error)
                        return "syncMessage." + error;
                }
            }
            if (message.dandelionStem != null && message.hasOwnProperty("dandelionStem")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.DandelionStem.verify(message.dandelionStem);
                    if (error)
                        return "dandelionStem." + error;
                }
            }
            if (message.swapPropose != null && message.hasOwnProperty("swapPropose")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.AtomicSwap.verify(message.swapPropose);
                    if (error)
                        return "swapPropose." + error;
                }
            }
            if (message.swapRespond != null && message.hasOwnProperty("swapRespond")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.AtomicSwap.verify(message.swapRespond);
                    if (error)
                        return "swapRespond." + error;
                }
            }
            if (message.swapAliceAdaptorSig != null && message.hasOwnProperty("swapAliceAdaptorSig")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.SwapAliceAdaptorSig.verify(message.swapAliceAdaptorSig);
                    if (error)
                        return "swapAliceAdaptorSig." + error;
                }
            }
            if (message.channelPropose != null && message.hasOwnProperty("channelPropose")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.ChannelProposal.verify(message.channelPropose);
                    if (error)
                        return "channelPropose." + error;
                }
            }
            if (message.channelAccept != null && message.hasOwnProperty("channelAccept")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.ChannelAcceptance.verify(message.channelAccept);
                    if (error)
                        return "channelAccept." + error;
                }
            }
            if (message.channelFundNonce != null && message.hasOwnProperty("channelFundNonce")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.ChannelNonce.verify(message.channelFundNonce);
                    if (error)
                        return "channelFundNonce." + error;
                }
            }
            if (message.channelFundSig != null && message.hasOwnProperty("channelFundSig")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.ChannelPartialSig.verify(message.channelFundSig);
                    if (error)
                        return "channelFundSig." + error;
                }
            }
            if (message.channelPayPropose != null && message.hasOwnProperty("channelPayPropose")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.PaymentProposal.verify(message.channelPayPropose);
                    if (error)
                        return "channelPayPropose." + error;
                }
            }
            if (message.channelPayAccept != null && message.hasOwnProperty("channelPayAccept")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.PaymentAcceptance.verify(message.channelPayAccept);
                    if (error)
                        return "channelPayAccept." + error;
                }
            }
            if (message.channelCloseNonce != null && message.hasOwnProperty("channelCloseNonce")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.ChannelNonce.verify(message.channelCloseNonce);
                    if (error)
                        return "channelCloseNonce." + error;
                }
            }
            if (message.channelCloseSig != null && message.hasOwnProperty("channelCloseSig")) {
                if (properties.payload === 1)
                    return "payload: multiple values";
                properties.payload = 1;
                {
                    var error = $root.p2p.ChannelPartialSig.verify(message.channelCloseSig);
                    if (error)
                        return "channelCloseSig." + error;
                }
            }
            return null;
        };

        /**
         * Creates a P2pMessage message from a plain object. Also converts values to their respective internal types.
         * @function fromObject
         * @memberof p2p.P2pMessage
         * @static
         * @param {Object.<string,*>} object Plain object
         * @returns {p2p.P2pMessage} P2pMessage
         */
        P2pMessage.fromObject = function fromObject(object) {
            if (object instanceof $root.p2p.P2pMessage)
                return object;
            var message = new $root.p2p.P2pMessage();
            if (object.block != null) {
                if (typeof object.block !== "object")
                    throw TypeError(".p2p.P2pMessage.block: object expected");
                message.block = $root.p2p.Block.fromObject(object.block);
            }
            if (object.transaction != null) {
                if (typeof object.transaction !== "object")
                    throw TypeError(".p2p.P2pMessage.transaction: object expected");
                message.transaction = $root.p2p.Transaction.fromObject(object.transaction);
            }
            if (object.blockAnnouncement != null) {
                if (typeof object.blockAnnouncement !== "object")
                    throw TypeError(".p2p.P2pMessage.blockAnnouncement: object expected");
                message.blockAnnouncement = $root.p2p.BlockAnnouncement.fromObject(object.blockAnnouncement);
            }
            if (object.blockRequest != null) {
                if (typeof object.blockRequest !== "object")
                    throw TypeError(".p2p.P2pMessage.blockRequest: object expected");
                message.blockRequest = $root.p2p.BlockRequest.fromObject(object.blockRequest);
            }
            if (object.getHashesRequest != null) {
                if (typeof object.getHashesRequest !== "object")
                    throw TypeError(".p2p.P2pMessage.getHashesRequest: object expected");
                message.getHashesRequest = $root.p2p.GetHashesRequest.fromObject(object.getHashesRequest);
            }
            if (object.hashesResponse != null) {
                if (typeof object.hashesResponse !== "object")
                    throw TypeError(".p2p.P2pMessage.hashesResponse: object expected");
                message.hashesResponse = $root.p2p.HashesResponse.fromObject(object.hashesResponse);
            }
            if (object.syncMessage != null) {
                if (typeof object.syncMessage !== "object")
                    throw TypeError(".p2p.P2pMessage.syncMessage: object expected");
                message.syncMessage = $root.p2p.SyncMessage.fromObject(object.syncMessage);
            }
            if (object.dandelionStem != null) {
                if (typeof object.dandelionStem !== "object")
                    throw TypeError(".p2p.P2pMessage.dandelionStem: object expected");
                message.dandelionStem = $root.p2p.DandelionStem.fromObject(object.dandelionStem);
            }
            if (object.swapPropose != null) {
                if (typeof object.swapPropose !== "object")
                    throw TypeError(".p2p.P2pMessage.swapPropose: object expected");
                message.swapPropose = $root.p2p.AtomicSwap.fromObject(object.swapPropose);
            }
            if (object.swapRespond != null) {
                if (typeof object.swapRespond !== "object")
                    throw TypeError(".p2p.P2pMessage.swapRespond: object expected");
                message.swapRespond = $root.p2p.AtomicSwap.fromObject(object.swapRespond);
            }
            if (object.swapAliceAdaptorSig != null) {
                if (typeof object.swapAliceAdaptorSig !== "object")
                    throw TypeError(".p2p.P2pMessage.swapAliceAdaptorSig: object expected");
                message.swapAliceAdaptorSig = $root.p2p.SwapAliceAdaptorSig.fromObject(object.swapAliceAdaptorSig);
            }
            if (object.channelPropose != null) {
                if (typeof object.channelPropose !== "object")
                    throw TypeError(".p2p.P2pMessage.channelPropose: object expected");
                message.channelPropose = $root.p2p.ChannelProposal.fromObject(object.channelPropose);
            }
            if (object.channelAccept != null) {
                if (typeof object.channelAccept !== "object")
                    throw TypeError(".p2p.P2pMessage.channelAccept: object expected");
                message.channelAccept = $root.p2p.ChannelAcceptance.fromObject(object.channelAccept);
            }
            if (object.channelFundNonce != null) {
                if (typeof object.channelFundNonce !== "object")
                    throw TypeError(".p2p.P2pMessage.channelFundNonce: object expected");
                message.channelFundNonce = $root.p2p.ChannelNonce.fromObject(object.channelFundNonce);
            }
            if (object.channelFundSig != null) {
                if (typeof object.channelFundSig !== "object")
                    throw TypeError(".p2p.P2pMessage.channelFundSig: object expected");
                message.channelFundSig = $root.p2p.ChannelPartialSig.fromObject(object.channelFundSig);
            }
            if (object.channelPayPropose != null) {
                if (typeof object.channelPayPropose !== "object")
                    throw TypeError(".p2p.P2pMessage.channelPayPropose: object expected");
                message.channelPayPropose = $root.p2p.PaymentProposal.fromObject(object.channelPayPropose);
            }
            if (object.channelPayAccept != null) {
                if (typeof object.channelPayAccept !== "object")
                    throw TypeError(".p2p.P2pMessage.channelPayAccept: object expected");
                message.channelPayAccept = $root.p2p.PaymentAcceptance.fromObject(object.channelPayAccept);
            }
            if (object.channelCloseNonce != null) {
                if (typeof object.channelCloseNonce !== "object")
                    throw TypeError(".p2p.P2pMessage.channelCloseNonce: object expected");
                message.channelCloseNonce = $root.p2p.ChannelNonce.fromObject(object.channelCloseNonce);
            }
            if (object.channelCloseSig != null) {
                if (typeof object.channelCloseSig !== "object")
                    throw TypeError(".p2p.P2pMessage.channelCloseSig: object expected");
                message.channelCloseSig = $root.p2p.ChannelPartialSig.fromObject(object.channelCloseSig);
            }
            return message;
        };

        /**
         * Creates a plain object from a P2pMessage message. Also converts values to other types if specified.
         * @function toObject
         * @memberof p2p.P2pMessage
         * @static
         * @param {p2p.P2pMessage} message P2pMessage
         * @param {$protobuf.IConversionOptions} [options] Conversion options
         * @returns {Object.<string,*>} Plain object
         */
        P2pMessage.toObject = function toObject(message, options) {
            if (!options)
                options = {};
            var object = {};
            if (message.block != null && message.hasOwnProperty("block")) {
                object.block = $root.p2p.Block.toObject(message.block, options);
                if (options.oneofs)
                    object.payload = "block";
            }
            if (message.transaction != null && message.hasOwnProperty("transaction")) {
                object.transaction = $root.p2p.Transaction.toObject(message.transaction, options);
                if (options.oneofs)
                    object.payload = "transaction";
            }
            if (message.blockAnnouncement != null && message.hasOwnProperty("blockAnnouncement")) {
                object.blockAnnouncement = $root.p2p.BlockAnnouncement.toObject(message.blockAnnouncement, options);
                if (options.oneofs)
                    object.payload = "blockAnnouncement";
            }
            if (message.blockRequest != null && message.hasOwnProperty("blockRequest")) {
                object.blockRequest = $root.p2p.BlockRequest.toObject(message.blockRequest, options);
                if (options.oneofs)
                    object.payload = "blockRequest";
            }
            if (message.getHashesRequest != null && message.hasOwnProperty("getHashesRequest")) {
                object.getHashesRequest = $root.p2p.GetHashesRequest.toObject(message.getHashesRequest, options);
                if (options.oneofs)
                    object.payload = "getHashesRequest";
            }
            if (message.hashesResponse != null && message.hasOwnProperty("hashesResponse")) {
                object.hashesResponse = $root.p2p.HashesResponse.toObject(message.hashesResponse, options);
                if (options.oneofs)
                    object.payload = "hashesResponse";
            }
            if (message.syncMessage != null && message.hasOwnProperty("syncMessage")) {
                object.syncMessage = $root.p2p.SyncMessage.toObject(message.syncMessage, options);
                if (options.oneofs)
                    object.payload = "syncMessage";
            }
            if (message.dandelionStem != null && message.hasOwnProperty("dandelionStem")) {
                object.dandelionStem = $root.p2p.DandelionStem.toObject(message.dandelionStem, options);
                if (options.oneofs)
                    object.payload = "dandelionStem";
            }
            if (message.swapPropose != null && message.hasOwnProperty("swapPropose")) {
                object.swapPropose = $root.p2p.AtomicSwap.toObject(message.swapPropose, options);
                if (options.oneofs)
                    object.payload = "swapPropose";
            }
            if (message.swapRespond != null && message.hasOwnProperty("swapRespond")) {
                object.swapRespond = $root.p2p.AtomicSwap.toObject(message.swapRespond, options);
                if (options.oneofs)
                    object.payload = "swapRespond";
            }
            if (message.swapAliceAdaptorSig != null && message.hasOwnProperty("swapAliceAdaptorSig")) {
                object.swapAliceAdaptorSig = $root.p2p.SwapAliceAdaptorSig.toObject(message.swapAliceAdaptorSig, options);
                if (options.oneofs)
                    object.payload = "swapAliceAdaptorSig";
            }
            if (message.channelPropose != null && message.hasOwnProperty("channelPropose")) {
                object.channelPropose = $root.p2p.ChannelProposal.toObject(message.channelPropose, options);
                if (options.oneofs)
                    object.payload = "channelPropose";
            }
            if (message.channelAccept != null && message.hasOwnProperty("channelAccept")) {
                object.channelAccept = $root.p2p.ChannelAcceptance.toObject(message.channelAccept, options);
                if (options.oneofs)
                    object.payload = "channelAccept";
            }
            if (message.channelFundNonce != null && message.hasOwnProperty("channelFundNonce")) {
                object.channelFundNonce = $root.p2p.ChannelNonce.toObject(message.channelFundNonce, options);
                if (options.oneofs)
                    object.payload = "channelFundNonce";
            }
            if (message.channelFundSig != null && message.hasOwnProperty("channelFundSig")) {
                object.channelFundSig = $root.p2p.ChannelPartialSig.toObject(message.channelFundSig, options);
                if (options.oneofs)
                    object.payload = "channelFundSig";
            }
            if (message.channelPayPropose != null && message.hasOwnProperty("channelPayPropose")) {
                object.channelPayPropose = $root.p2p.PaymentProposal.toObject(message.channelPayPropose, options);
                if (options.oneofs)
                    object.payload = "channelPayPropose";
            }
            if (message.channelPayAccept != null && message.hasOwnProperty("channelPayAccept")) {
                object.channelPayAccept = $root.p2p.PaymentAcceptance.toObject(message.channelPayAccept, options);
                if (options.oneofs)
                    object.payload = "channelPayAccept";
            }
            if (message.channelCloseNonce != null && message.hasOwnProperty("channelCloseNonce")) {
                object.channelCloseNonce = $root.p2p.ChannelNonce.toObject(message.channelCloseNonce, options);
                if (options.oneofs)
                    object.payload = "channelCloseNonce";
            }
            if (message.channelCloseSig != null && message.hasOwnProperty("channelCloseSig")) {
                object.channelCloseSig = $root.p2p.ChannelPartialSig.toObject(message.channelCloseSig, options);
                if (options.oneofs)
                    object.payload = "channelCloseSig";
            }
            return object;
        };

        /**
         * Converts this P2pMessage to JSON.
         * @function toJSON
         * @memberof p2p.P2pMessage
         * @instance
         * @returns {Object.<string,*>} JSON object
         */
        P2pMessage.prototype.toJSON = function toJSON() {
            return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
        };

        /**
         * Gets the default type url for P2pMessage
         * @function getTypeUrl
         * @memberof p2p.P2pMessage
         * @static
         * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
         * @returns {string} The default type url
         */
        P2pMessage.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
            if (typeUrlPrefix === undefined) {
                typeUrlPrefix = "type.googleapis.com";
            }
            return typeUrlPrefix + "/p2p.P2pMessage";
        };

        return P2pMessage;
    })();

    return p2p;
})();

module.exports = $root;
