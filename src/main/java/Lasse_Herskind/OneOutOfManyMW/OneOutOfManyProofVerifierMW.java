package Lasse_Herskind.OneOutOfManyMW;

import Lasse_Herskind.LelantusConstants;
import Lasse_Herskind.LelantusUtils;
import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;

import java.math.BigInteger;
import java.util.ArrayList;

public class OneOutOfManyProofVerifierMW<T extends GroupElement<T>> implements Verifier<DoubleGeneratorParams<T>, T[], OneOutOfManyProofMW<T>> {
    @Override
    public void verify(DoubleGeneratorParams<T> params, T[] CMList, OneOutOfManyProofMW<T> proof) throws VerificationFailedException {
        int n = LelantusConstants.n;
        int m = LelantusConstants.m;
        int N = (int) Math.pow(n, m);

        BigInteger q = params.getGroup().groupOrder();
        VectorBase vectorBase = params.getVectorBase();

        BigInteger x = LelantusUtils.getChallenge(params, proof);// ProofUtils.computeChallenge(q, proof.getA(), proof.getB(), proof.getC(), proof.getD());

        BigInteger[][] fs = proof.getFs();
        for (int j = 0; j < m; j++) {
            fs[j][0] = x;
            for (int i = 1; i < n; i++) {
                fs[j][0] = fs[j][0].subtract(fs[j][i]);
            }
        }

        GroupElement BxA = proof.getB().multiply(x).add(proof.getA());
        FieldVector fVector = getFVector(fs, q);
        GroupElement fVectorTest = vectorBase.commit(fVector, proof.getzA());
        if (!BxA.equals(fVectorTest)) {
            throw new VerificationFailedException();
        }

        BigInteger[][] fs2 = new BigInteger[m][n];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                BigInteger temp = x.subtract(fs[j][i]);
                fs2[j][i] = fs[j][i].multiply(temp);
            }
        }

        GroupElement CxD = proof.getC().multiply(x).add(proof.getD());
        FieldVector f2Vector = getFVector(fs2, q);
        GroupElement f2VectorTest = vectorBase.commit(f2Vector, proof.getzC());
        if (!CxD.equals(f2VectorTest)) {
            throw new VerificationFailedException();
        }

        int[] i_bin = getNAry(0, n, m);
        GroupElement C_0 = CMList[0];
        BigInteger exponent = BigInteger.ONE;
        for (int j = 0; j < m; j++) {
            exponent = exponent.multiply(fs[j][i_bin[j]]);
        }
        C_0 = C_0.multiply(exponent);

        GroupElement bigFucker1 = C_0;
        for (int i = 1; i < N; i++) {
            i_bin = getNAry(i, n, m);
            GroupElement C_i = CMList[i];
            exponent = BigInteger.ONE;
            for (int j = 0; j < m; j++) {
                exponent = exponent.multiply(fs[j][i_bin[j]]);
            }
            C_i = C_i.multiply(exponent); // Remember that C_i is group element, so ^ becomes *
            bigFucker1 = bigFucker1.add(C_i); // and * becomes +
        }

        GroupElement[] Gks = proof.getGks();
        GroupElement[] Qks = proof.getQks();

        GroupElement bigFucker2 = Gks[0].add(Qks[0]).multiply(x.pow(0).negate()); // Could be issues here
        for (int k = 1; k < m; k++) {
            GroupElement temp = Gks[k].add(Qks[k]).multiply(x.pow(k).negate());
            bigFucker2 = bigFucker2.add(temp);
        }

        GroupElement bigFucker = bigFucker1.add(bigFucker2);
        GroupElement comm = getDBPedersen(params, BigInteger.ZERO, BigInteger.ZERO, proof.getzR()).getCommitment();
        if (!bigFucker.equals(comm)) {
            throw new VerificationFailedException();
        }
    }

    private DoubleBlindedPedersenCommitment<T> getDBPedersen(DoubleGeneratorParams params, BigInteger serial, BigInteger value, BigInteger r2) {
        return new DoubleBlindedPedersenCommitment(params.getBase(), serial, value, r2);
    }

    private static int[] getNAry(int val, int n, int m) {
        int[] return_val = new int[m];
        int i = m - 1;
        while (val != 0) {
            int q = val / n;
            int r = val - q * n;
            return_val[i] = r;
            val = q;
            i--;
        }
        return return_val;
    }

    private static FieldVector getFVector(BigInteger[][] fs, BigInteger q) {
        ArrayList<BigInteger> fs_list = new ArrayList<>();
        for (int i = 0; i < fs[0].length; i++) {
            for (int j = 0; j < fs.length; j++) {
                fs_list.add(fs[j][i]);
            }
        }
        return FieldVector.from(VectorX.fromIterator(fs_list.iterator()), q);
    }
}
