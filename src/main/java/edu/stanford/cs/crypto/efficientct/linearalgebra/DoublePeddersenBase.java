package edu.stanford.cs.crypto.efficientct.linearalgebra;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.circuit.groups.Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;

import java.math.BigInteger;

/**
 * Created by buenz on 7/2/17.
 */
public class DoublePeddersenBase<T extends GroupElement<T>> extends GeneratorVector<T> {
    public final T g;
    public final T h;
    public final T j;

    public DoublePeddersenBase(T g, T h, T j, Group<T> group) {
        super(VectorX.of(g, h, j), group);
        this.g = g;
        this.h = h;
        this.j = j;
    }

    public T commit(BigInteger x, BigInteger r, BigInteger r2) {
        return g.multiply(x).add(h.multiply(r)).add(j.multiply(r2));
    }

}
