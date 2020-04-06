package soot.jimple.toolkits.annotation.aaamyPack;

import soot.*;
import soot.jimple.IdentityStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.ParameterRef;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class TaintedAnnotator extends BodyTransformer {
    private static TaintedAnnotator instance = new TaintedAnnotator();

    private TaintedAnnotator() {
    }

    public static TaintedAnnotator v() {
        return instance;
    }

    protected void internalTransform(Body b, String phaseName, Map options) {
        SootMethod sootMethod = b.getMethod();
        System.out.println("Propagating on method: " + sootMethod.getName());
        Body activeBody = sootMethod.getActiveBody();
        activeBody.addTag(new TaintedTag(1));
        UnitPatchingChain units = activeBody.getUnits();

        List<Local> parameterLocals = getParameterLocals(units);
        int[] sensitiveParamIndexes = determineSensitiveParamIndexes(parameterLocals);
        sootMethod.addTag(new TaintedTag(sensitiveParamIndexes));

        parameterLocals.forEach(this::processLocal);

        taintedAnalyse(sootMethod);
//        for (Unit s : units) {
//            if (s instanceof IdentityStmt &&
//                    ((IdentityStmt) s).getRightOp() instanceof ParameterRef) {
//                IdentityStmt is = (IdentityStmt) s;
//                Value leftBoxValue = ((JIdentityStmt) is).leftBox.getValue();
//                if (leftBoxValue.toString().equalsIgnoreCase("y")) {
//                    System.out.println("You playing with fire");
//                    leftBoxValue.getUseBoxes();
//                    //search for uses of leftBox and annotate them
//                }
//                ParameterRef pr = (ParameterRef) is.getRightOp();
//            }
//        }
    }

    private int[] determineSensitiveParamIndexes(List<Local> parameterLocals) {
        if (parameterLocals.size() == 0)
            return new int[0];
        int[] indexes = new int[parameterLocals.size()];
        indexes[0] = 1;
        return indexes;
    }

    private void taintedAnalyse(SootMethod sootMethod) {
        TaintedTag taintedTag = (TaintedTag) sootMethod.getTag("pf.bm.TaintedTag");
        int[] indexes = taintedTag.getTaintedParamIndex();

        Body activeBody = sootMethod.getActiveBody();
        UnitPatchingChain units = activeBody.getUnits();
        List<Local> parameterLocals = getParameterLocals(units);

        units.forEach(curUnit -> {
            if (curUnit instanceof InvokeStmt) {
                InvokeStmt invokeStmt = (InvokeStmt) curUnit;
                InvokeExpr expr = invokeStmt.getInvokeExpr();
                SootMethod currentMethod = expr.getMethod();
                List<Value> args = expr.getArgs();
                int[] newTaintedIndexes = new int[args.size()];
                int c = 0;

                for (Value arg : args) {
                    int index = findIndex(parameterLocals, arg);
                    if (index != -1)
                        newTaintedIndexes[c++] = 1;
                }

                if (currentMethod.getName().equals("println") || currentMethod.getName().equals("print")) {
                    System.out.println("Found dangerous method: " + sootMethod.getName());

                    for (Value arg : args) {
                        int index = findIndex(parameterLocals, arg);
                        if (index != -1)
                            System.out.println("HIGHWAY TO THE DANGER-ZONE");
                    }
                }

                boolean found = args.stream().anyMatch(arg -> parameterLocals.stream().anyMatch(param -> param.getName().equals(arg.toString())));

                if (found) {
                    currentMethod.addTag(new TaintedTag(newTaintedIndexes));
                    taintedAnalyse(currentMethod);
                }
            }
        });
    }

    private int findIndex(List<Local> paramLocals, Value argument) {
        for (int i = 0; i < paramLocals.size(); i++) {
            if (paramLocals.get(i).getName().equals(argument.toString())) {
                return i;
            }
        }
        return -1;
    }

    private List<ValueBox> processLocal(Local local) {
        return local.getUseBoxes();
    }

    public List<Local> getParameterLocals(UnitPatchingChain units) {
        final List<Local> retVal = new ArrayList<>();

        //try to annotate here somehow
        //Parameters are zero-indexed, so the keeping of the index is safe
        for (Unit u : units) {
            if (u instanceof IdentityStmt) {
                IdentityStmt identityStmt = ((IdentityStmt) u);
                if (identityStmt.getRightOp() instanceof ParameterRef) {
                    ParameterRef pr = (ParameterRef) identityStmt.getRightOp();
                    retVal.add(pr.getIndex(), (Local) identityStmt.getLeftOp());
                }
            }
        }
        return retVal;
    }

}

