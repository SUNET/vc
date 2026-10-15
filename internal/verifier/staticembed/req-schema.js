import * as v from "valibot";

/**
 * reqSchema validates a circuit_zk `req` WITHOUT rebuilding it.
 *
 * `req` is the circuit_zk format's list of requested calculations, and its
 * `params` are inputs to a proof: the server passes them through exactly
 * as an operator configured them, and so must the browser. A parameter
 * silently removed on the way out is a different proof input, which is a
 * different pseudonym - computed from a request nobody wrote.
 *
 * Valibot's object schemas REBUILD their output, and two of their rules
 * drop data here:
 *
 *   - `v.record` excludes the prototype-polluting keys, so a parameter
 *     named `constructor` or `prototype` is validated and then dropped.
 *   - `v.looseObject` collects the item's extras but not inherited-name
 *     keys like `toString`, so an item extension named that is dropped.
 *
 * Measured, not assumed (valibot 1.1.0):
 *
 *   params in  -> config, constructor, prototype, normal
 *   params out -> config, normal
 *   item   in  -> id, return, params, toString, extra
 *   item   out -> id, return, params, extra
 *
 * So the shape is CHECKED and the original value is handed back
 * untouched: `v.any()` performs no transformation, and `v.check` cannot,
 * by construction. The cost is that InferOutput is `any` rather than a
 * typed item - which is the right trade, because the alternative is a
 * type that lies about what was sent.
 *
 * One definition, imported by every schema that carries a `req`. Fixing
 * one schema and not the other loses the parameters anyway, so there is
 * only one to fix.
 */
export const reqSchema = v.pipe(
    v.any(),
    v.check(
        (items) =>
            Array.isArray(items) &&
            items.every(
                (item) =>
                    item !== null &&
                    typeof item === "object" &&
                    !Array.isArray(item) &&
                    typeof item.id === "string" &&
                    typeof item.return === "string" &&
                    (item.params === undefined ||
                        (typeof item.params === "object" &&
                            item.params !== null &&
                            !Array.isArray(item.params))),
            ),
        "req must be an array of {id, return, params?} items",
    ),
);
