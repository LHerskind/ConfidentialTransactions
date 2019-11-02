package Lasse_Herskind.OneOutOfManyMW;

import Lasse_Herskind.LelantusConstants;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
import edu.stanford.cs.crypto.efficientct.Prover;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class OneOutOfManyProofProverMW<T extends GroupElement<T>> implements Prover<DoubleGeneratorParams<T>, T[], OneOutOfManyWitnessMW<T>, OneOutOfManyProofMW<T>> {
    @Override
    public OneOutOfManyProofMW<T> generateProof(DoubleGeneratorParams<T> parameter, T[] CMList, OneOutOfManyWitnessMW<T> witness) {
        int n = LelantusConstants.n;
        int m = LelantusConstants.m;
        int N = (int) Math.pow(n, m);

        BigInteger q = parameter.getGroup().groupOrder();

        VectorBase vectorBase = parameter.getVectorBase();
        int[] l_bin = getNAry(witness.getL(), n, m);
        BigInteger rA = ProofUtils.randomNumber();
        BigInteger rB = ProofUtils.randomNumber();

        BigInteger rC = ProofUtils.randomNumber();
        BigInteger rD = ProofUtils.randomNumber();
        BigInteger[][] a = generateA(n, m);

        GroupElement A = vectorBase.commit(getAVector(a, n, m, q), rA);
        GroupElement B = vectorBase.commit(getBVector(l_bin, n, m, q), rB);
        GroupElement C = vectorBase.commit(getCVector(a, l_bin, n, m, q), rC);
        GroupElement D = vectorBase.commit(getDVector(a, n, m, q), rD);

        GroupElement[] Gks = new GroupElement[m];
        GroupElement[] Qks =  new GroupElement[m];
        BigInteger[] rhok =  new BigInteger[m];
        BigInteger[] tauk =  new BigInteger[m];
        BigInteger[] gammak =  new BigInteger[m];

        BigInteger[][] Pi_ks = new BigInteger[N][m];
        Set<Integer> indexes = new HashSet<>();
        for(int i = 0 ; i < N; i++){
            indexes.add(i);
        }
        indexes.parallelStream().forEach((i -> {
            Pi_ks[i] = calculatePks_i(l_bin, a, i, n, m);
        }));

        Set<Integer> indexesK = new HashSet<>();
        for(int i = 0 ; i < m; i++){
            indexesK.add(i);
        }

        indexesK.parallelStream().forEach(k -> {
            BigInteger rho = BigInteger.ZERO;
            BigInteger tau = ProofUtils.randomNumber();
            BigInteger gamma = ProofUtils.randomNumber();

            rhok[k] = rho;
            tauk[k] = tau;
            gammak[k] = gamma;

            GroupElement Gk = CMList[0].multiply(Pi_ks[0][k]);
            for(int i = 1 ; i < N; i++){
                Gk = Gk.add(CMList[i].multiply(Pi_ks[i][k]));
            }
            Gk = Gk.add(parameter.getBase().j.multiply(gamma.negate()));
            Gks[k] = Gk;

            GroupElement Qk = parameter.getBase().j.multiply(gamma).add(getDBPedersen(parameter, BigInteger.ZERO, rho, tau).getCommitment());
            Qks[k] = Qk;
        });

        BigInteger x =  ProofUtils.computeChallenge(q);

        BigInteger[][] fs = new BigInteger[m][n];
        for(int i = 1; i < n; i++){
            for(int j = 0 ; j < m; j++){
                fs[j][i] = f(l_bin, a, j, i, x);
            }
        }

        BigInteger zA = rB.multiply(x).add(rA);
        BigInteger zC = rC.multiply(x).add(rD);
        BigInteger zR = witness.getR().multiply(x.pow(m));
        for(int k = 0 ; k < m; k++){
            zR = zR.subtract(tauk[k].multiply(x.pow(k)));
        }

        witness.setGammaK(gammak);

        return new OneOutOfManyProofMW<>(A, B, C, D, Gks, Qks, fs, zA, zC, zR);
    }
    private DoubleBlindedPedersenCommitment<T> getDBPedersen(DoubleGeneratorParams params, BigInteger serial, BigInteger value, BigInteger r2){
        return new DoubleBlindedPedersenCommitment(params.getBase(), serial, value, r2);
    }

    private static Set<Set<Integer>> getCombinations(int m, int number_of_sigmas) {
        Set<Integer> to_combine = new HashSet<>();
        for (int i = 0; i < m; i++) {
            to_combine.add(i);
        }
        return Sets.combinations(ImmutableSet.copyOf(to_combine), number_of_sigmas);
    }

    private static BigInteger[] calculatePks_i(int[] l_bin, BigInteger[][] a, int i_val, int n, int m) {
        int[] i_bin = getNAry(i_val, n, m);
        BigInteger[] ks = new BigInteger[m];

        for (int k = 0; k < m; k++) {
            BigInteger Pi_k = BigInteger.ZERO;
            for (Set<Integer> combination : getCombinations(m, k)) {
                BigInteger temp = BigInteger.ONE;
                for (int j = 0; j < m; j++) {
                    if (combination.contains(j)) {
                        temp = temp.multiply(sigma(l_bin[j], i_bin[j]));
                    } else {
                        temp = temp.multiply(a[j][i_bin[j]]);
                    }
                }
                Pi_k = Pi_k.add(temp);
            }
            ks[k] = Pi_k;
        }

        return ks;
    }

    private static BigInteger f(int[] l_bin, BigInteger[][] a, int j, int i, BigInteger x) {
        return sigma(l_bin[j], i).multiply(x).add(a[j][i]);
    }

    private static BigInteger sigma(int j, int i) {
        if (j == i) {
            return BigInteger.ONE;
        }
        return BigInteger.ZERO;
    }

    private static FieldVector getDVector(BigInteger[][] a, int n, int m, BigInteger q) {
        ArrayList<BigInteger> d_list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                d_list.add(a[j][i].multiply(a[j][i]).negate());
            }
        }
        return FieldVector.from(VectorX.fromIterator(d_list.iterator()), q);
    }

    private static FieldVector getCVector(BigInteger[][] a, int[] l_bin, int n, int m, BigInteger q) {
        ArrayList<BigInteger> c_list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                BigInteger elem_1 = a[j][i];
                BigInteger elem_2 = BigInteger.ONE.subtract(BigInteger.TWO.multiply(sigma(l_bin[j], i)));
                c_list.add(elem_1.multiply(elem_2));
            }
        }
        return FieldVector.from(VectorX.fromIterator(c_list.iterator()), q);
    }

    private static FieldVector getBVector(int[] l_bin, int n, int m, BigInteger q) {
        ArrayList<BigInteger> b_list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                b_list.add(sigma(l_bin[j], i));
            }
        }
        return FieldVector.from(VectorX.fromIterator(b_list.iterator()), q);
    }

    private static FieldVector getAVector(BigInteger[][] a, int n, int m, BigInteger q) {
        ArrayList<BigInteger> a_list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                a_list.add(a[j][i]);
            }
        }
        return FieldVector.from(VectorX.fromIterator(a_list.iterator()), q);
    }

    private static BigInteger[][] generateA(int n, int m) {
        BigInteger[][] A = new BigInteger[m][n];
        for (int i = 1; i < n; i++) {
            for (int j = 0; j < m; j++) {
                A[j][i] = ProofUtils.randomNumber();
            }
        }
        for (int j = 0; j < m; j++) {
            A[j][0] = BigInteger.ZERO;
            for (int i = 1; i < n; i++) {
                A[j][0] = A[j][0].subtract(A[j][i]);
            }
        }
        return A;
    }

    private static int[] getNAry(int val, int n, int m){
        int[] return_val = new int[m];
        int i = m-1;
        while(val != 0){
            int q = val / n;
            int r = val - q*n;
            return_val[i] = r;
            val = q;
            i--;
        }
        return return_val;
    }
}

