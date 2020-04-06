package soot.jimple.toolkits.annotation.aaamyPack;

import soot.Body;
import soot.BodyTransformer;

import java.util.Map;

public class TaintedAnalyser extends BodyTransformer {
    private static TaintedAnalyser instance = new TaintedAnalyser();

    private TaintedAnalyser() {
    }

    public static TaintedAnalyser v() {
        return instance;
    }

    static String oldPath;

    protected void internalTransform(Body b, String phaseName, Map options) {
        System.out.println("Analyzing method: " + b.getMethod().getName());
        b.getMethod().getActiveBody().getTags().forEach(System.out::print);
        System.out.println();
    }
}
