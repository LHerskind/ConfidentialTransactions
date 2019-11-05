package Lasse_Herskind.LelantusMW;

import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProof;
import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProofProver;
import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProofVerifier;
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
import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BN128Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;

/**
 * This is a joinsplit where we try to use a NORMAL one-out-of-many proof, and then instead pass the outputs,
 * ONLY afterwards, to ensure that no value was created.
 */

public class Spending_Mint_One_of_each_Clean_V5_MW {

    private static BN128Group curve;
    private static DoubleGeneratorParams params;

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
        GeneralizedSchnorrProofProver generalizedSchnorrProofProver = new GeneralizedSchnorrProofProver();
        GeneralizedSchnorrProofVerifier generalizedSchnorrProofVerifier = new GeneralizedSchnorrProofVerifier();

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

        DoubleBlindedPedersenCommitment serialNumber = LelantusUtils.getDBPedersen(params, S, BigInteger.ZERO, BigInteger.ZERO); // .add(output_coin);
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

        OneOutOfManyProofProver oneOutOfManyProofProver = new OneOutOfManyProofProver();
        OneOutOfManyProofVerifier oneOutOfManyProofVerifier = new OneOutOfManyProofVerifier();

        OneOutOfManyWitness oneOutOfManyWitness = new OneOutOfManyWitness(N - 1, shielded_coin);
        OneOutOfManyProof oneOutOfManyProof = oneOutOfManyProofProver.generateProof(params, CMList, oneOutOfManyWitness);
        oneOutOfManyProofVerifier.verify(params, CMList, oneOutOfManyProof);

        // Can we make the A, but here just as a double-blinded so we can extract the other when we need it.
        BigInteger private_A = LelantusUtils.getAPrivate(params, oneOutOfManyProof, oneOutOfManyWitness);
        GroupElement public_A = LelantusUtils.getAPublic(params, oneOutOfManyProof);
        // Then we actually make some change to
        BigInteger x = LelantusUtils.getChallenge(params, oneOutOfManyProof);
        System.out.println("Just V: " + params.getBase().h.multiply(V.multiply(x.pow(m))));
        System.out.println("The output: " + output_coin);

        System.out.println(params.getBase().h.multiply(output_coin.times(x.pow(m)).getValue()));
        public_A = output_coin.times(x.pow(m)).getCommitment().subtract(public_A);

        BigInteger offset_from_output_coin = output_coin.getRandom().multiply(x.pow(m));
        private_A = offset_from_output_coin.subtract(private_A);

        System.out.println(public_A);
        System.out.println(params.getBase().j.multiply(private_A));

        System.out.println("Did we come all the way down here!?");

        if (!public_A.equals(LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.ZERO, private_A).getCommitment())) {
            throw new VerificationFailedException();
        }

        /* TODO: What is the transaction we are trying to make
         * We have a shielded output with value of 25, and a normal output of value 10.
         * We want to end up with a shielded of 30, and a normal of 5.
         * Shielded_in -> CoinOutput
         * CoinOutput + Normal_in -> To_shield + Normal_out
         * To_shield -> Shielded_out
         */

        // The above is pretty much just what do for the one-out-of-many proofs. Now let us make the minting of a new coin
        // Remember output_coin, the coin retrieved from the spending!
        DoubleBlindedPedersenCommitment normalSource = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.valueOf(10), ProofUtils.randomNumber());

        // We should not use the serial number here, but instead the output, RIGHT!?
        DoubleBlindedPedersenCommitment publishedSource = output_coin.sub(LelantusUtils.getDBPedersen(params, q, BigInteger.ZERO, private_A));
        if (!(output_coin.getCommitment().subtract(public_A.add(Q))).equals(publishedSource.getCommitment())) {
            // Is it ok do to so, hence we only ourself in this? Maybe we have issues with Q, if I could make A the reverse of Q?
            // I could make the output_coin == Q? Then the need for me to actually sign would be removed. However, I could not make the proof as v != 0.
            // The other oppoturnity is that A = -Q, that requires sum(zr+gamma) to be -Q, which seems to be as hard as brute-forcing Q. Could be a decent check after all.
            // We make a check, but we really need to have this somewhere that is actually validated, i.e., need to be shown in the protocol.
            // Can we discard the output? We pretty much need it for the actual proof right? We here have C+A+Q
            // ISSUES
            // Seems like we have an issue, when this is included in the places where we actually perform
            // This is a spending check, we spend a count
            // What is this check, we check that the
            System.out.println("LORT");
            //throw new VerificationFailedException();
        }

        DoubleBlindedPedersenCommitment excess_shielded = output_coin.sub(publishedSource);
        System.out.println("Excess shielded: " + excess_shielded);
        GeneralizedSchnorrProof generalizedSchnorrProofShielded = generalizedSchnorrProofProver.generateProof(params, excess_shielded.getCommitment(), excess_shielded);
        generalizedSchnorrProofVerifier.verify(params, excess_shielded.getCommitment(), generalizedSchnorrProofShielded);

        // Now the normal transfer, i.e, coin_output + normal_in -> normal_out + to_shield
        DoubleBlindedPedersenCommitment normalDestination = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.valueOf(5), ProofUtils.randomNumber());
        BigInteger V_mint = (normalSource.getValue().add(shielded_coin.getValue()).subtract(normalDestination.getValue())); // This is pretty much an intermediate value
        BigInteger R_mint = ProofUtils.randomNumber();
        DoubleBlindedPedersenCommitment to_shield = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, V_mint, R_mint);

        DoubleBlindedPedersenCommitment excess_normal = normalDestination.add(to_shield).sub(output_coin.add(normalSource));
        System.out.println("Normal excess: " + excess_normal);
        if(!excess_normal.getCommitment().equals(params.getBase().j.multiply(excess_normal.getRandom()))){
            System.out.println("Issues! Sig not matching");
        }

        // Now minting the shielded transaction, i.e., to_shield -> shielded
        BigInteger q_mint = ProofUtils.randomNumber();
        GroupElement Q_mint = params.getBase().g.multiply(q_mint);
        BigInteger S_mint = ProofUtils.hash(Q_mint.toString());
        BigInteger R_offset_mint = ProofUtils.randomNumber();

        // Generating D = C * G^s * J^{r_{offset}}
        DoubleBlindedPedersenCommitment shieldedCoinNew = LelantusUtils.getDBPedersen(params, S_mint, BigInteger.ZERO, R_offset_mint).add(to_shield);

        // Ensuring that we are able to spend the inputs we want to move to the shielded pool, i.e., that we know the openings.
        GeneralizedSchnorrProof generalizedSchnorrProof2 =  generalizedSchnorrProofProver.generateProofNoS(params, to_shield.getCommitment(), to_shield);
        generalizedSchnorrProofVerifier.verifyNoS(params, to_shield.getCommitment(), generalizedSchnorrProof2);

        DoubleBlindedPedersenCommitment excess_shielded_out = shieldedCoinNew.sub(to_shield);
        System.out.println("Excess shielded out: " + excess_shielded_out);

        // The kernel offset, we can do this for every kernel. Simply split it into (excess, excess_offset, GSP | Signature)
        //BigInteger k_offset = ProofUtils.randomNumber();
        //excess_shielded_out = excess_shielded_out.sub(LelantusUtils.getDBPedersen(params, BigInteger.ZERO, BigInteger.ZERO, k_offset));

        GeneralizedSchnorrProof GSPShieldedIn = generalizedSchnorrProofProver.generateProofNoS(params, to_shield.getCommitment(), to_shield);
        generalizedSchnorrProofVerifier.verifyNoS(params, to_shield.getCommitment(), GSPShieldedIn);

        GeneralizedSchnorrProof GSPExcessShieldedOut = generalizedSchnorrProofProver.generateProof(params, excess_shielded_out.getCommitment(), excess_shielded_out);
        generalizedSchnorrProofVerifier.verify(params, excess_shielded_out.getCommitment(), GSPExcessShieldedOut);

        // Now we can add all the excess
        DoubleBlindedPedersenCommitment excess_total = excess_shielded.add(excess_normal).add(excess_shielded_out);
        System.out.println("Excess total: " + excess_total);

        // Now, we calculate the excess and see what happens
        DoubleBlindedPedersenCommitment excess_inputs = normalSource.add(publishedSource).add(to_shield).add(output_coin);
        DoubleBlindedPedersenCommitment excess_outputs = normalDestination.add(output_coin).add(to_shield).add(shieldedCoinNew);

        DoubleBlindedPedersenCommitment excess = excess_outputs.sub(excess_inputs);
        System.out.println("Excess: " + excess);
        if(excess.getCommitment().equals(excess_total.getCommitment())){
            System.out.println("It works");
        }


        System.out.println(System.currentTimeMillis() - start_time);
    }


}
