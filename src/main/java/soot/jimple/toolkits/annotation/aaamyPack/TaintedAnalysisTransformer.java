package soot.jimple.toolkits.annotation.aaamyPack;

import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.Targets;
import soot.util.dot.DotGraph;

import java.util.*;
import java.util.stream.StreamSupport;

public class TaintedAnalysisTransformer extends BodyTransformer {
    private static TaintedAnalysisTransformer instance = new TaintedAnalysisTransformer();

    private static final List<String> dangerousMethods = Arrays.asList("java.io.PrintStream.write");

    private TaintedAnalysisTransformer() {
    }

    public static TaintedAnalysisTransformer v() {
        return instance;
    }

    protected void internalTransform(Body b, String phaseName, Map options) {
        SootMethod sootMethod = b.getMethod();
        System.out.println("Entry point: " + sootMethod.getName());

        List<Local> parameterLocals = getParameterLocals(sootMethod);
        int[] sensitiveParamIndexes = determineSensitiveParamIndexes(parameterLocals);
        sootMethod.removeTag("pf.bm.TaintedTag");
        sootMethod.addTag(new TaintedTag(sensitiveParamIndexes));

        analyseSootMethod(sootMethod);

        reportUnsafeParameters(sootMethod, parameterLocals);
    }

    private String extractMethodName(SootMethod sootMethod) {
        return sootMethod.getDeclaringClass() + "." + sootMethod.getName();
    }

    private void reportUnsafeParameters(SootMethod sootMethod, List<Local> parameterLocals) {
        String methodFullName = extractMethodName(sootMethod);
        TaintedTag taintedTag = (TaintedTag) sootMethod.getTag("pf.bm.TaintedTag");
        int[] sensitiveParamIndexes = taintedTag.getSensitiveParamsIndexes();
        int[] compromisedIndexes = taintedTag.getCompromisedParamIndexes();

        for (int i = 0; i < compromisedIndexes.length; i++) {
            if (compromisedIndexes[i] == 1 && sensitiveParamIndexes[i] == 1) {
                System.out.println("Parameter " + parameterLocals.get(i).getName() + " of method " + methodFullName + " is unsafe");
            }
        }
    }

    private int[] determineSensitiveParamIndexes(List<Local> parameterLocals) {
        if (parameterLocals.size() == 0)
            return new int[0];
        int[] indexes = new int[parameterLocals.size()];
        Arrays.fill(indexes, 1);
        return indexes;
    }

    private void analyseSootMethod(SootMethod sootMethod) {
        CallGraph callGraph = Scene.v().getCallGraph();

        List<Local> parameterLocals = getParameterLocals(sootMethod);

        if (sootMethod.getName().equals("<init>")) {
            return;
        }

        Iterator<Edge> edges = callGraph.edgesOutOf(sootMethod);
        StreamSupport
                .stream(Spliterators.spliteratorUnknownSize(edges, Spliterator.ORDERED), false)
                .forEach(e -> searchForCompromisedIndexes(parameterLocals, e, sootMethod));
    }

    private TaintedTag storeAnalysisResultOnTag(SootMethod sootMethod, int[] compromisedIndexes) {
        TaintedTag taintedTag = getOrCreateTaintedTag(sootMethod, compromisedIndexes.length);

        taintedTag.setVisited(true);
        taintedTag.updateCompromisedParamIndexes(compromisedIndexes);
        return taintedTag;
    }

    private TaintedTag getOrCreateTaintedTag(SootMethod sootMethod, int paramLocalSize) {
        TaintedTag taintedTag = (TaintedTag) sootMethod.getTag("pf.bm.TaintedTag");

        if (taintedTag == null) {
            taintedTag = new TaintedTag(new int[paramLocalSize]);
            sootMethod.addTag(taintedTag);
        }
        return taintedTag;
    }

    private void searchForCompromisedIndexes(List<Local> parameterLocals, Edge e, SootMethod parentMethod) {
        Unit unit = e.srcUnit();
        if (unit instanceof InvokeStmt) {
            InvokeExpr expr = ((InvokeStmt) unit).getInvokeExpr();
            SootMethod currentMethod = expr.getMethod();
            List<Value> args = expr.getArgs();
            int[] compromisedIndexes = new int[parameterLocals.size()];

            String fullMethodName = extractMethodName(currentMethod);

            if (dangerousMethods.contains(fullMethodName)) {
                for (Value arg : args) {
                    int index = findIndex(parameterLocals, arg);

                    if (index != -1) {
                        compromisedIndexes[index] = 1;
                    }
                }
                storeAnalysisResultOnTag(currentMethod, compromisedIndexes);
                updateParentTag(parameterLocals, args, parentMethod, compromisedIndexes);

                //System.out.println("Found dangerous method: " + currentMethod.getName() + " with " + taintedTag.toString());
            } else {
                analyzeInvokedMethods(parameterLocals, currentMethod, args, parentMethod);
            }
        }
    }

    private void analyzeInvokedMethods(List<Local> parameterLocals, SootMethod invokedMethod, List<Value> args, SootMethod parentMethod) {
        boolean nextMethodUsesParams = args.stream().anyMatch(arg -> parameterLocals.stream().anyMatch(param -> param.getName().equals(arg.toString())));
        int[] compromisedIndexes = new int[args.size()];

        if (nextMethodUsesParams) {
            TaintedTag taintedTag = getOrCreateTaintedTag(invokedMethod, args.size());
            //System.out.println("T1 dangerous method: " + invokedMethod.getName() + " with " + taintedTag.toString());
            if (!taintedTag.isVisited()) {
                //System.out.println("VISITING " + invokedMethod.getName());
                analyseSootMethod(invokedMethod);
                storeAnalysisResultOnTag(invokedMethod, compromisedIndexes);
            }

            //System.out.println("T2 dangerous method: " + invokedMethod.getName() + " with " + taintedTag.toString());

            taintedTag = getOrCreateTaintedTag(invokedMethod, args.size());
            int[] compromisedArguments = taintedTag.getCompromisedParamIndexes();
            //System.out.println("Cargs of method " + invokedMethod.getName() +": " + Arrays.toString(compromisedArguments));

            updateParentTag(parameterLocals, args, parentMethod, compromisedArguments);
        }
    }

    private void updateParentTag(List<Local> parameterLocals, List<Value> args, SootMethod parentMethod, int[] compromisedArguments) {
        int[] parentCompromisedIndexes = new int[parameterLocals.size()];
        for (int i = 0; i < compromisedArguments.length; i++) {
            if (compromisedArguments[i] == 1) {
                Value argument = args.get(i);

                int paramIndex = findIndex(parameterLocals, argument);
                if (paramIndex != -1)
                    parentCompromisedIndexes[paramIndex] = 1;
            }
        }

        storeAnalysisResultOnTag(parentMethod, parentCompromisedIndexes);
    }

    private List<Local> getParameterLocals(SootMethod sootMethod) {
        Body activeBody;

        try {
            activeBody = sootMethod.getActiveBody();
        } catch (Exception e) {
            System.out.println("skipping method: " + sootMethod.getName() + ", reason: " + e.getMessage());
            return new ArrayList<>();
        }
        UnitPatchingChain units = activeBody.getUnits();
        final List<Local> retVal = new ArrayList<>();

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

    private int findIndex(List<Local> paramLocals, Value argument) {
        for (int i = 0; i < paramLocals.size(); i++) {
            if (paramLocals.get(i).getName().equals(argument.toString())) {
                return i;
            }
        }
        return -1;
    }

    @Deprecated
    private static void visit(CallGraph cg, SootMethod method) {
        String identifier = method.getSignature();
        Map<String, Boolean> visited = new HashMap<>();
        visited.put(method.getSignature(), true);
        DotGraph dot = new DotGraph("hellograph");
        dot.drawNode(identifier);
        // iterate over unvisited parents
        Iterator<MethodOrMethodContext> ptargets = new Targets(cg.edgesInto(method));

        while (ptargets.hasNext()) {
            SootMethod parent = (SootMethod) ptargets.next();
            if (!visited.containsKey(parent.getSignature())) visit(cg, parent);
        }

        // iterate over unvisited children
        Iterator<MethodOrMethodContext> ctargets = new Targets(cg.edgesOutOf(method));

        while (ctargets.hasNext()) {
            SootMethod child = (SootMethod) ctargets.next();
            dot.drawEdge(identifier, child.getSignature());
            System.out.println(method + " may call " + child);
            if (!visited.containsKey(child.getSignature())) visit(cg, child);
        }

    }

    @Deprecated
    private void taintedAnalyse(SootMethod sootMethod) {
        TaintedTag taintedTag = (TaintedTag) sootMethod.getTag("pf.bm.TaintedTag");
        //int[] indexes = taintedTag.getSensitiveParamsIndexes();
        Body activeBody;
        try {
            activeBody = sootMethod.getActiveBody();
        } catch (Exception e) {
            System.out.println("skipping method: " + sootMethod.getName() + ", reason: " + e.getMessage());
            return;
        }
        UnitPatchingChain units = activeBody.getUnits();
//        List<Local> parameterLocals = getParameterLocals(sootMethod);
//
//        units.forEach(curUnit -> {
//            if (curUnit instanceof InvokeStmt) {
//                analyseInvokeStatement(parameterLocals, (InvokeStmt) curUnit);
//            } else if (curUnit instanceof AssignStmt) { //no good
//                AssignStmt assignStmt = (AssignStmt) curUnit;
//                List<ValueBox> useBoxes = assignStmt.getUseBoxes();
//                useBoxes.forEach(box -> {
//                    Tag tag = box.getTag("pf.bm.TaintedTag");
//                    if (tag != null) {
//                        assignStmt.getDefBoxes().get(0).addTag(tag);
//                    }
//                });
//            }
//        });
    }
}

