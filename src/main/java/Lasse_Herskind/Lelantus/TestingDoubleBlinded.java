package Lasse_Herskind.Lelantus;

import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BN128Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;

import java.math.BigInteger;

public class TestingDoubleBlinded {

    private static DoubleBlindedPedersenCommitment getDBPedersen(DoubleGeneratorParams params, int x, int r1, int r2){
        return new DoubleBlindedPedersenCommitment(params.getBase(), BigInteger.valueOf(x), BigInteger.valueOf(r1), BigInteger.valueOf(r2));
    }

    private static DoubleBlindedPedersenCommitment getDBPedersen(DoubleGeneratorParams params, int x){
        return new DoubleBlindedPedersenCommitment(params.getBase(), BigInteger.valueOf(x));
    }

    public static void main(String[] args){

        BN128Group curve = new BN128Group();
        GeneratorParams smallParams = GeneratorParams.generateParams(1, curve);
        DoubleGeneratorParams params = DoubleGeneratorParams.generateParams(1, curve);
        //System.out.println(smallParams.getBase().g + " : " + smallParams.getBase().h);
        //System.out.println(params.getBase().g + " : " + params.getBase().h + " : " + params.getBase().j);


        DoubleBlindedPedersenCommitment c1 = getDBPedersen(params, 25, 234, 531);
        PeddersenCommitment dc = new PeddersenCommitment(smallParams.getBase(), BigInteger.valueOf(25), BigInteger.valueOf(234));
        DoubleBlindedPedersenCommitment cRemove = getDBPedersen(params, 0, 0, 531);

        System.out.println("DoubleBlinded: " + c1.getCommitment().stringRepresentation());
        System.out.println("Normal commitment :\t\t" + dc.getCommitment().stringRepresentation());
        System.out.println("Doubleblinded - r2*J:\t" + (c1.getCommitment().subtract(cRemove.getCommitment())).stringRepresentation());
        System.out.println("----");

        DoubleBlindedPedersenCommitment c2 = getDBPedersen(params, 5);
        DoubleBlindedPedersenCommitment c3 = c1.add(c2);
        GroupElement e1 = c1.getCommitment();
        GroupElement e2 = c2.getCommitment();
        System.out.println("Commitment 1: " + e1.stringRepresentation());
        System.out.println("Commitment 2: " + e2.stringRepresentation());

        GroupElement e3 = e1.add(e2);
        System.out.println("Commitments added:\t\t\t" + e3.stringRepresentation());
        System.out.println("Creating new commitment:\t" + c3.getCommitment().stringRepresentation());
    }


}
