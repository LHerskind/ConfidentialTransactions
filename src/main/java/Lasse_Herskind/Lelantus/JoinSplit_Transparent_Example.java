package Lasse_Herskind.Lelantus;

import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProof;
import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProofProver;
import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProofVerifier;
import Lasse_Herskind.LelantusUtils;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyProof;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyProofProver;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyProofVerifier;
import Lasse_Herskind.OneOutOfMany.OneOutOfManyWitness;
import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BN128Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;

public class JoinSplit_Transparent_Example {

    private static BN128Group curve;
    private static DoubleGeneratorParams params;

    private static void init(int size) {
        curve = new BN128Group();
        params = DoubleGeneratorParams.generateParams(size, curve);
    }

    public static void main(String[] args) throws VerificationFailedException {
        int n = 2;
        int m = 2;
        int N = (int) Math.pow(n, m);
        System.out.println("n: " + n + ", m: " + m + ", N: " + N);
        init(N);

        // We will try to make two transfer in the same transaction, i.e., 2 inputs of 25 need to become a output of 15, one of 5 and one of 30.

        // Create two transaction that can be used for this shit!
        BigInteger V_i1 = BigInteger.valueOf(25);
        BigInteger q_i1 = ProofUtils.randomNumber();
        GroupElement Q_i1 = params.getBase().g.multiply(q_i1);
        BigInteger S_i1 = ProofUtils.hash(Q_i1.toString());
        BigInteger R_i1 = ProofUtils.randomNumber();
        DoubleBlindedPedersenCommitment coin_i1 = LelantusUtils.getDBPedersen(params, S_i1, V_i1, R_i1);

        BigInteger V_i2 = BigInteger.valueOf(25);
        BigInteger q_i2 = ProofUtils.randomNumber();
        GroupElement Q_i2 = params.getBase().g.multiply(q_i2);
        BigInteger S_i2 = ProofUtils.hash(Q_i2.toString());
        BigInteger R_i2 = ProofUtils.randomNumber();
        DoubleBlindedPedersenCommitment coin_i2 = LelantusUtils.getDBPedersen(params, S_i2, V_i2, R_i2);

        System.out.println("coin_i1: \t\t" + coin_i1.getCommitment().stringRepresentation());
        System.out.println("coin_i2: \t\t" + coin_i2.getCommitment().stringRepresentation());

        // Now creating the two outputs
        BigInteger V_o1 = BigInteger.valueOf(15);
        BigInteger q_o1 = ProofUtils.randomNumber();
        GroupElement Q_o1 = params.getBase().g.multiply(q_o1);
        BigInteger S_o1 = ProofUtils.hash(Q_o1.toString());
        BigInteger R_o1 = ProofUtils.randomNumber();
        DoubleBlindedPedersenCommitment coin_o1 = LelantusUtils.getDBPedersen(params, S_o1, V_o1, R_o1);

        BigInteger V_o2 = BigInteger.valueOf(5);
        BigInteger q_o2 = ProofUtils.randomNumber();
        GroupElement Q_o2 = params.getBase().g.multiply(q_o2);
        BigInteger S_o2 = ProofUtils.hash(Q_o2.toString());
        BigInteger R_o2 = ProofUtils.randomNumber();
        DoubleBlindedPedersenCommitment coin_o2 = LelantusUtils.getDBPedersen(params, S_o2, V_o2, R_o2);

        BigInteger V_o3 = BigInteger.valueOf(25);
        BigInteger q_o3 = ProofUtils.randomNumber();
        GroupElement Q_o3 = params.getBase().g.multiply(q_o3);
        BigInteger S_o3 = ProofUtils.hash(Q_o3.toString());
        BigInteger R_o3 = ProofUtils.randomNumber();
        DoubleBlindedPedersenCommitment coin_o3 = LelantusUtils.getDBPedersen(params, S_o3, V_o3, R_o3);

        // And then finally, I want to extract some coins transparently
        BigInteger V_t = BigInteger.valueOf(5);

        System.out.println("coin_o1: \t\t" + coin_o1.getCommitment().stringRepresentation());
        System.out.println("coin_o2: \t\t" + coin_o2.getCommitment().stringRepresentation());
        System.out.println("coin_o3: \t\t" + coin_o3.getCommitment().stringRepresentation());
        System.out.println("transperant: \t" + V_t);

        // Generate the CMLists
        DoubleBlindedPedersenCommitment serialNumber1 = LelantusUtils.getDBPedersen(params, S_i1, BigInteger.ZERO, BigInteger.ZERO);
        DoubleBlindedPedersenCommitment serialNumber2 = LelantusUtils.getDBPedersen(params, S_i2, BigInteger.ZERO, BigInteger.ZERO);
        System.out.println("Serial Number Point1: " + serialNumber1.getCommitment().stringRepresentation());
        System.out.println("Serial Number Point2: " + serialNumber2.getCommitment().stringRepresentation());

        GroupElement[] CMList1 = new GroupElement[N];
        GroupElement[] CMList2 = new GroupElement[N];
        for (int i = 0; i < N - 1; i++) {
            CMList1[i] = LelantusUtils.getDBPedersen(params, BigInteger.valueOf(i + 1)).getCommitment();
            CMList2[i] = LelantusUtils.getDBPedersen(params, BigInteger.valueOf(i + 1)).getCommitment();
        }
        CMList1[N - 1] = coin_i1.getCommitment();
        CMList2[N - 1] = coin_i2.getCommitment();
        for (int i = 0; i < N; i++) {
            CMList1[i] = CMList1[i].subtract(serialNumber1.getCommitment());
            CMList2[i] = CMList2[i].subtract(serialNumber2.getCommitment());
        }

        // The spend proofs!
        OneOutOfManyProofProver oneOutOfManyProofProver = new OneOutOfManyProofProver();
        OneOutOfManyProofVerifier oneOutOfManyProofVerifier = new OneOutOfManyProofVerifier();

        OneOutOfManyWitness oneOutOfManyWitness1 = new OneOutOfManyWitness(N - 1, coin_i1);
        OneOutOfManyProof oneOutOfManyProof1 = oneOutOfManyProofProver.generateProof(params, CMList1, oneOutOfManyWitness1);
        oneOutOfManyProofVerifier.verify(params, CMList1, oneOutOfManyProof1);

        OneOutOfManyWitness oneOutOfManyWitness2 = new OneOutOfManyWitness(N - 1, coin_i2);
        OneOutOfManyProof oneOutOfManyProof2 = oneOutOfManyProofProver.generateProof(params, CMList2, oneOutOfManyWitness2);
        oneOutOfManyProofVerifier.verify(params, CMList2, oneOutOfManyProof2);

        // Now for the interesting stuff!
        // TODO: Implement the new bulletproofs so that we actually perform these!

        // Prove that no value is created!
        BigInteger x = LelantusUtils.getChallenge(params, oneOutOfManyProof1);

        GroupElement transparent = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, V_t, BigInteger.ZERO).getCommitment();
        GroupElement A = (coin_o1.add(coin_o2).add(coin_o3).getCommitment()).multiply(x.pow(m)).add(transparent.multiply(x.pow(m)));

        BigInteger zV = oneOutOfManyProof1.getzV().add(oneOutOfManyProof2.getzV());
        BigInteger zR = oneOutOfManyProof1.getzR().add(oneOutOfManyProof2.getzR());
        GroupElement B = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, zV, zR).getCommitment();

        GroupElement[] Qks1 = oneOutOfManyProof1.getQks();
        GroupElement[] Qks2 = oneOutOfManyProof2.getQks();

        for(int k = 0 ; k < m; k++) {
            GroupElement temp = Qks1[k].add(Qks2[k]).multiply(x.pow(k));
            B = B.add(temp);
        }

        GroupElement aDivB = A.subtract(B);

        BigInteger X = (S_o1.add(S_o2).add(S_o3)).multiply(x.pow(m)).mod(params.getGroup().groupOrder());

        BigInteger Y1 = (R_o1.add(R_o2).add(R_o3)).multiply(x.pow(m));

        BigInteger Y21 = R_i1.multiply(x.pow(m));
        BigInteger Y22 = R_i2.multiply(x.pow(m));

        BigInteger[] gammak1 = oneOutOfManyWitness1.getGammaK();
        BigInteger[] gammak2 = oneOutOfManyWitness2.getGammaK();

        for(int k = 0; k < m; k++){
            Y21 = Y21.add(gammak1[k].multiply(x.pow(k)));
            Y22 = Y22.add(gammak2[k].multiply(x.pow(k)));
        }
        BigInteger Y2 = Y21.add(Y22);
        BigInteger Y = Y1.subtract(Y2).mod(params.getGroup().groupOrder());

        DoubleBlindedPedersenCommitment discreteLogRelation = LelantusUtils.getDBPedersen(params, X, BigInteger.ZERO, Y);

        GeneralizedSchnorrProofProver generalizedSchnorrProofProver = new GeneralizedSchnorrProofProver();
        GeneralizedSchnorrProofVerifier generalizedSchnorrProofVerifier = new GeneralizedSchnorrProofVerifier();

        GeneralizedSchnorrProof generalizedSchnorrProof =  generalizedSchnorrProofProver.generateProof(params, aDivB, discreteLogRelation);
        generalizedSchnorrProofVerifier.verify(params, discreteLogRelation.getCommitment(), generalizedSchnorrProof);
    }
}
