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
         * @property {Uint8Array|null} [rangeProof] TransactionOutput rangeProof
         * @property {Uint8Array|null} [ephemeralKey] TransactionOutput ephemeralKey
         * @property {Uint8Array|null} [stealthPayload] TransactionOutput stealthPayload
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
         * TransactionOutput rangeProof.
         * @member {Uint8Array} rangeProof
         * @memberof p2p.TransactionOutput
         * @instance
         */
        TransactionOutput.prototype.rangeProof = $util.newBuffer([]);

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
            if (message.rangeProof != null && Object.hasOwnProperty.call(message, "rangeProof"))
                writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.rangeProof);
            if (message.ephemeralKey != null && Object.hasOwnProperty.call(message, "ephemeralKey"))
                writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.ephemeralKey);
            if (message.stealthPayload != null && Object.hasOwnProperty.call(message, "stealthPayload"))
                writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.stealthPayload);
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
                case 2: {
                        message.rangeProof = reader.bytes();
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
            if (message.rangeProof != null && message.hasOwnProperty("rangeProof"))
                if (!(message.rangeProof && typeof message.rangeProof.length === "number" || $util.isString(message.rangeProof)))
                    return "rangeProof: buffer expected";
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
            if (object.rangeProof != null)
                if (typeof object.rangeProof === "string")
                    $util.base64.decode(object.rangeProof, message.rangeProof = $util.newBuffer($util.base64.length(object.rangeProof)), 0);
                else if (object.rangeProof.length >= 0)
                    message.rangeProof = object.rangeProof;
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
            if (options.defaults) {
                if (options.bytes === String)
                    object.commitment = "";
                else {
                    object.commitment = [];
                    if (options.bytes !== Array)
                        object.commitment = $util.newBuffer(object.commitment);
                }
                if (options.bytes === String)
                    object.rangeProof = "";
                else {
                    object.rangeProof = [];
                    if (options.bytes !== Array)
                        object.rangeProof = $util.newBuffer(object.rangeProof);
                }
            }
            if (message.commitment != null && message.hasOwnProperty("commitment"))
                object.commitment = options.bytes === String ? $util.base64.encode(message.commitment, 0, message.commitment.length) : options.bytes === Array ? Array.prototype.slice.call(message.commitment) : message.commitment;
            if (message.rangeProof != null && message.hasOwnProperty("rangeProof"))
                object.rangeProof = options.bytes === String ? $util.base64.encode(message.rangeProof, 0, message.rangeProof.length) : options.bytes === Array ? Array.prototype.slice.call(message.rangeProof) : message.rangeProof;
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
            if (options.defaults)
                if ($util.Long) {
                    var long = new $util.Long(0, 0, true);
                    object.timestamp = options.longs === String ? long.toString() : options.longs === Number ? long.toNumber() : long;
                } else
                    object.timestamp = options.longs === String ? "0" : 0;
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

        // OneOf field names bound to virtual getters and setters
        var $oneOfFields;

        /**
         * P2pMessage payload.
         * @member {"block"|"transaction"|"blockAnnouncement"|"blockRequest"|"getHashesRequest"|"hashesResponse"|"syncMessage"|"dandelionStem"|undefined} payload
         * @memberof p2p.P2pMessage
         * @instance
         */
        Object.defineProperty(P2pMessage.prototype, "payload", {
            get: $util.oneOfGetter($oneOfFields = ["block", "transaction", "blockAnnouncement", "blockRequest", "getHashesRequest", "hashesResponse", "syncMessage", "dandelionStem"]),
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
