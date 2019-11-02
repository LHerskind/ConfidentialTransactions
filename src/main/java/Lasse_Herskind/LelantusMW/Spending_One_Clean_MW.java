package Lasse_Herskind.LelantusMW;

import Lasse_Herskind.LelantusConstants;
import Lasse_Herskind.LelantusUtils;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyProof;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyProofProver;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyProofVerifier;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyWitness;
import Lasse_Herskind.OneOutOfManyMW.OneOutOfManyProofMW;
import Lasse_Herskind.OneOutOfManyMW.OneOutOfManyProofProverMW;
import Lasse_Herskind.OneOutOfManyMW.OneOutOfManyProofVerifierMW;
import Lasse_Herskind.OneOutOfManyMW.OneOutOfManyWitnessMW;
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
import java.util.HashSet;
import java.util.Set;

public class Spending_One_Clean_MW {

    private static BN128Group curve;
    private static DoubleGeneratorParams params;
    private static int[] l_bin;
    private static BigInteger[][] a;

    private static void init(int size) {
        curve = new BN128Group();
        params = DoubleGeneratorParams.generateParams(size, curve);
    }

    public static void main(String[] args) throws VerificationFailedException {
        /**
         * In this one we try do something else.
         * Instead of extracting some value V, we will extract the a commitment output_coin
         * Which is a normal Pedersen commitment, i.e., gV+hR.
         */

        long start_time = System.currentTimeMillis();

        // First, we need to make an anonymity set, let us use n = 2 and m = 2 for N = 4
        int n = LelantusConstants.n;
        int m = LelantusConstants.m;
        int N = (int) Math.pow(n, m);
        System.out.println("n: " + n + ", m: " + m + ", N: " + N);
        init(N);

        // We Mint the transaction
        BigInteger V = BigInteger.valueOf(25);
        BigInteger q = ProofUtils.randomNumber();
        GroupElement Q = params.getBase().g.multiply(q);
        BigInteger S = ProofUtils.hash(Q.toString());
        BigInteger R = ProofUtils.randomNumber();

        DoubleBlindedPedersenCommitment shielded_coin = LelantusUtils.getDBPedersen(params, S, V, R);
        System.out.println("shielded_coin: \t\t\t\t" + shielded_coin.getCommitment().stringRepresentation());

        DoubleBlindedPedersenCommitment output_coin = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, V, ProofUtils.randomNumber());
        System.out.println("coin_extracted: \t" + output_coin.getCommitment().stringRepresentation());

        System.out.println("--- spending ---");

        System.out.println("Reveal S: " + S);

        DoubleBlindedPedersenCommitment serialNumber = LelantusUtils.getDBPedersen(params, S, BigInteger.ZERO, BigInteger.ZERO).add(output_coin);
        System.out.println("Serial Number Point: " + serialNumber.getCommitment().stringRepresentation());

        // TODO: Implement the 1-out-of-N proofs below!

        GroupElement[] CMList = new GroupElement[N];
        for (int i = 0; i < N - 1; i++) {
            CMList[i] = LelantusUtils.getDBPedersen(params, BigInteger.valueOf(i + 1)).getCommitment();
        }
        CMList[N - 1] = shielded_coin.getCommitment();
        for (int i = 0; i < N; i++) {
            CMList[i] = CMList[i].subtract(serialNumber.getCommitment());
        }

        OneOutOfManyProofProverMW oneOutOfManyProofProverMW = new OneOutOfManyProofProverMW();
        OneOutOfManyProofVerifierMW oneOutOfManyProofVerifierMW = new OneOutOfManyProofVerifierMW();

        OneOutOfManyWitnessMW oneOutOfManyWitnessMW = new OneOutOfManyWitnessMW(N-1, shielded_coin, output_coin);
        OneOutOfManyProofMW oneOutOfManyProofMW = oneOutOfManyProofProverMW.generateProof(params, CMList, oneOutOfManyWitnessMW);
        oneOutOfManyProofVerifierMW.verify(params, CMList, oneOutOfManyProofMW);

        BigInteger private_A = LelantusUtils.getAPrivate(params, oneOutOfManyProofMW, oneOutOfManyWitnessMW);
        GroupElement public_A = LelantusUtils.getAPublic(params, oneOutOfManyProofMW);

        if (!public_A.equals(LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.ZERO, private_A).getCommitment())) {
            throw new VerificationFailedException();
        }

        System.out.println("It works");

        System.out.println(System.currentTimeMillis() - start_time);
    }



}
