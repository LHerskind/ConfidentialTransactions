package Lasse_Herskind.Lelantus;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BN128Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SpendingExample2 {

    private static BN128Group curve;
    private static DoubleGeneratorParams params;
    private static int[] l_bin;
    private static BigInteger[][] a;

    private static DoubleBlindedPedersenCommitment getDBPedersen(BigInteger serial,BigInteger value, BigInteger r2){
        return new DoubleBlindedPedersenCommitment(params.getBase(), serial, value, r2);
    }

    private static DoubleBlindedPedersenCommitment getDBPedersen(BigInteger x) {
        return new DoubleBlindedPedersenCommitment(params.getBase(), x);
    }

    private static void init(int size) {
        curve = new BN128Group();
        params = DoubleGeneratorParams.generateParams(size, curve);
    }

    public static void main(String[] args) throws VerificationFailedException {

        long start_time = System.currentTimeMillis();

        // First, we need to make an anonymity set, let us use n = 2 and m = 2 for N = 4
        int n = 2;
        int m = 2;
        int N = (int) Math.pow(n, m);
        System.out.println("n: " + n + ", m: " + m + ", N: " + N);
        init(N);

        // We Mint the transaction
        BigInteger V = BigInteger.valueOf(25);
        BigInteger q = ProofUtils.randomNumber();
        GroupElement Q = params.getBase().g.multiply(q);
        BigInteger S = ProofUtils.hash(Q.toString());
        BigInteger R = ProofUtils.randomNumber();

        DoubleBlindedPedersenCommitment coin = getDBPedersen(S, V, R);
        System.out.println("coin: \t\t" + coin.getCommitment().stringRepresentation());

        System.out.println("--- spending ---");

        System.out.println("Reveal S: " + S);

        DoubleBlindedPedersenCommitment serialNumber = getDBPedersen(S, BigInteger.ZERO, BigInteger.ZERO);
        System.out.println("Serial Number Point: " + serialNumber.getCommitment().stringRepresentation());

        // TODO: Implement the 1-out-of-N proofs below!
        ArrayList<DoubleBlindedPedersenCommitment> CMList = new ArrayList<>();
        for (int i = 0; i < N - 1; i++) {
            CMList.add(getDBPedersen(BigInteger.valueOf(i + 1)));
        }
        CMList.add(2, coin);
        ArrayList<DoubleBlindedPedersenCommitment> CMList_ = new ArrayList<>();
        for (DoubleBlindedPedersenCommitment commit : CMList) {
            CMList_.add(commit.sub(serialNumber));
        }

        VectorBase vectorBase = params.getVectorBase();
        int l = 2;
        l_bin = getNAry(l, n, m);
        BigInteger rA = ProofUtils.randomNumber();
        BigInteger rB = ProofUtils.randomNumber();

        BigInteger rC = ProofUtils.randomNumber();
        BigInteger rD = ProofUtils.randomNumber();
        a = generateA(n, m);

        GroupElement A = vectorBase.commit(getAVector(n, m), rA);
        GroupElement B = vectorBase.commit(getBVector(n, m), rB);
        GroupElement C = vectorBase.commit(getCVector(n, m), rC);
        GroupElement D = vectorBase.commit(getDVector(n, m), rD);

        // Now we need to do some computation on the commitments
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
            Pi_ks[i] = calculatePks_i(i, n, m);
        }));

        Set<Integer> indexesK = new HashSet<>();
        for(int i = 0 ; i < m; i++){
            indexesK.add(i);
        }

        indexesK.parallelStream().forEach(k -> {
            BigInteger rho = ProofUtils.randomNumber();
            BigInteger tau = ProofUtils.randomNumber();
            BigInteger gamma = ProofUtils.randomNumber();

            rhok[k] = rho;
            tauk[k] = tau;
            gammak[k] = gamma;

            GroupElement Gk = CMList_.get(0).getCommitment().multiply(Pi_ks[0][k]);
            for(int i = 1 ; i < N; i++){
                Gk = Gk.add(CMList_.get(i).getCommitment().multiply(Pi_ks[i][k]));
            }
            Gk = Gk.add(params.getBase().j.multiply(gamma.negate()));
            Gks[k] = Gk;

            GroupElement Qk = params.getBase().j.multiply(gamma).add(getDBPedersen(BigInteger.ZERO, rho, tau).getCommitment());
            Qks[k] = Qk;
        });

        // Start of verifier 1
        BigInteger x = ProofUtils.randomNumber();
        System.out.println("X: " + x);
        // End of verifier 1

        //ArrayList<BigInteger> fs = new ArrayList<>();
        BigInteger[][] fs = new BigInteger[m][n];
        for(int i = 1; i < n; i++){
            for(int j = 0 ; j < m; j++){
                fs[j][i] = f(j, i, x);
            }
        }

        BigInteger zA = rB.multiply(x).add(rA);
        BigInteger zC = rC.multiply(x).add(rD);
        BigInteger zV = V.multiply(x.pow(m));
        BigInteger zR = R.multiply(x.pow(m));
        for(int k = 0 ; k < m; k++){
            zV = zV.subtract(rhok[k].multiply(x.pow(k)));
            zR = zR.subtract(tauk[k].multiply(x.pow(k)));
        }

        // Start verifier 2
        for(int j = 0 ; j < m; j++){
            fs[j][0] = x;
            for(int i = 1 ; i < n; i++){
                fs[j][0] = fs[j][0].subtract(fs[j][i]);
            }
        }
        GroupElement BxA = B.multiply(x).add(A);
        // Check values
        FieldVector fVector = getFVector(fs);
        GroupElement fVectorTest = vectorBase.commit(fVector, zA);
        if (!BxA.equals(fVectorTest)){
            throw new VerificationFailedException();
        }

        BigInteger[][] fs2 = new BigInteger[m][n];
        for(int i = 0 ; i < n; i++){
            for(int j = 0 ; j < m; j++){
                BigInteger temp = x.subtract(fs[j][i]);
                fs2[j][i] = fs[j][i].multiply(temp);
            }
        }
        GroupElement CxD = C.multiply(x).add(D);
        FieldVector f2Vector = getFVector(fs2);
        GroupElement f2VectorTest = vectorBase.commit(f2Vector, zC);
        if(!CxD.equals(f2VectorTest)){
            throw new VerificationFailedException();
        }

        // Now the big motherfucker
        int[] i_bin = getNAry(0, n, m);
        GroupElement C_0 = CMList_.get(0).getCommitment();
        BigInteger exponent = BigInteger.ONE;
        for(int j= 0; j < m; j++){
            exponent = exponent.multiply(fs[j][i_bin[j]]);
        }
        C_0 = C_0.multiply(exponent);

        GroupElement bigFucker1 = C_0;
        for(int i = 1; i < N; i++){
            i_bin = getNAry(i, n, m);
            GroupElement C_i = CMList_.get(i).getCommitment();
            exponent = BigInteger.ONE;
            for(int j= 0; j < m; j++){
                exponent = exponent.multiply(fs[j][i_bin[j]]);
            }
            C_i = C_i.multiply(exponent); // Remember that C_i is group element, so ^ becomes *
            bigFucker1 = bigFucker1.add(C_i); // and * becomes +
        }

        GroupElement bigFucker2 = Gks[0].add(Qks[0]).multiply(x.pow(0).negate()); // Could be issues here
        for(int k = 1; k < m; k++){
            GroupElement temp = Gks[k].add(Qks[k]).multiply(x.pow(k).negate());
            bigFucker2 = bigFucker2.add(temp);
        }

        GroupElement bigFucker = bigFucker1.add(bigFucker2);
        GroupElement comm = getDBPedersen(BigInteger.ZERO, zV, zR).getCommitment();
        if(!bigFucker.equals(comm)){
            throw new VerificationFailedException();
        } else {
            System.out.println("BIGBRAIN");
        }

        // The proof of no value creation
        BigInteger witness_a = R.multiply(x.pow(m));
        for(int k = 0 ; k < m; k++){
            witness_a = witness_a.add(gammak[k].multiply(x.pow(k)));
        }
        witness_a.mod(curve.groupOrder());
        System.out.println(witness_a);

        GroupElement public_A = comm;
        for(int k = 0; k < m; k++){
            public_A = public_A.add(Qks[k].multiply(x.pow(k)));
        }
        public_A = public_A.subtract(getDBPedersen(BigInteger.ZERO, V, BigInteger.ZERO).getCommitment().multiply(x.pow(m)));

        System.out.println(public_A.stringRepresentation());
        System.out.println(getDBPedersen(BigInteger.ZERO, BigInteger.ZERO, witness_a).getCommitment().stringRepresentation());

        System.out.println(System.currentTimeMillis() - start_time);
    }

    private static FieldVector getFVector(BigInteger[][] fs) {
        ArrayList<BigInteger> fs_list = new ArrayList<>();
        for (int i = 0; i < fs[0].length; i++) {
            for (int j = 0; j < fs.length; j++) {
                fs_list.add(fs[j][i]);
            }
        }
        return FieldVector.from(VectorX.fromIterator(fs_list.iterator()), curve.groupOrder());
    }

    private static BigInteger f(int j, int i, BigInteger x) {
        return sigma(l_bin[j], i).multiply(x).add(a[j][i]);
    }

    private static BigInteger sigma(int j, int i) {
        if (j == i) {
            return BigInteger.ONE;
        }
        return BigInteger.ZERO;
    }

    private static Set<Set<Integer>> getCombinations(int m, int number_of_sigmas) {
        Set<Integer> to_combine = new HashSet<>();
        for (int i = 0; i < m; i++) {
            to_combine.add(i);
        }
        return Sets.combinations(ImmutableSet.copyOf(to_combine), number_of_sigmas);
    }

    private static BigInteger[] calculatePks_i(int i_val, int n, int m) {
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

    private static BigInteger calculateP_i(int i_val, int m, BigInteger x) {
        BigInteger P_i = BigInteger.ONE;
        int[] i = getBinary(i_val, m);
        for (int j = 0; j < m; j++) {
            P_i = P_i.multiply(f(j, i[j], x));
        }
        return P_i;
    }

    private static BigInteger calculateP_i2(int l, int i_val, int m, BigInteger x) {
        if (l == i_val) {
            return x.pow(m);
        }
        return BigInteger.ZERO;
    }

    private static FieldVector getDVector(int n, int m) {
        ArrayList<BigInteger> d_list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                d_list.add(a[j][i].multiply(a[j][i]).negate());
            }
        }
        return FieldVector.from(VectorX.fromIterator(d_list.iterator()), curve.groupOrder());
    }

    private static FieldVector getCVector(int n, int m) {
        ArrayList<BigInteger> c_list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                BigInteger elem_1 = a[j][i];
                BigInteger elem_2 = BigInteger.ONE.subtract(BigInteger.TWO.multiply(sigma(l_bin[j], i)));
                c_list.add(elem_1.multiply(elem_2));
            }
        }
        return FieldVector.from(VectorX.fromIterator(c_list.iterator()), curve.groupOrder());
    }

    private static FieldVector getBVector(int n, int m) {
        ArrayList<BigInteger> b_list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                b_list.add(sigma(l_bin[j], i));
            }
        }
        return FieldVector.from(VectorX.fromIterator(b_list.iterator()), curve.groupOrder());
    }

    private static FieldVector getAVector(int n, int m) {
        ArrayList<BigInteger> a_list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                a_list.add(a[j][i]);
            }
        }
        return FieldVector.from(VectorX.fromIterator(a_list.iterator()), curve.groupOrder());
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

    // TODO: Make this less shit
    private static int[] getBinary(int val, int m) {
        String binary_string = Integer.toBinaryString(val);
        int[] return_val = new int[m];
        int x_to_small = m - binary_string.length();
        for (int i = 0; i < binary_string.length(); i++) {
            return_val[i + x_to_small] = (int) binary_string.charAt(i) - 48;
        }
        return return_val;
    }


}
