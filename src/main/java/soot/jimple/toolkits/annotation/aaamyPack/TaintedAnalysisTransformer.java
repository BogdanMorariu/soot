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
        sootMethod.removeTag(TaintedTag.NAME);
        sootMethod.addTag(new TaintedTag(sensitiveParamIndexes));

        analyseNode(sootMethod);

        reportUnsafeParameters(sootMethod, parameterLocals);
    }

    private void reportUnsafeParameters(SootMethod sootMethod, List<Local> parameterLocals) {
        String methodFullName = extractMethodName(sootMethod);
        TaintedTag taintedTag = (TaintedTag) sootMethod.getTag(TaintedTag.NAME);
        int[] sensitiveParamIndexes = taintedTag.getSensitiveParamsIndexes();
        int[] compromisedIndexes = taintedTag.getCompromisedParamIndexes();

        for (int i = 0; i < compromisedIndexes.length; i++) {
            if (compromisedIndexes[i] == 1 && sensitiveParamIndexes[i] == 1) {
                System.out.println("Parameter " + parameterLocals.get(i).getName() + " of method " + methodFullName + " is unsafe");
            }
        }
    }

    private void analyseNode(SootMethod sootMethod) {
        CallGraph callGraph = Scene.v().getCallGraph();

        Iterator<Edge> edges = callGraph.edgesOutOf(sootMethod);
        StreamSupport.stream(Spliterators.spliteratorUnknownSize(edges, Spliterator.ORDERED), false)
                .forEach(this::analyzeEdge);
    }

    private void analyzeEdge(Edge e) {
        SootMethod parentMethod = e.getSrc().method();
        List<Local> parameterLocals = getParameterLocals(parentMethod);
        Unit unit = e.srcUnit();
        if (!(unit instanceof InvokeStmt)) {
            return;
        }
        SootMethod currentMethod = extractMethod(unit);
        List<Value> currentArguments = extractArguments(unit);

        String fullMethodName = extractMethodName(currentMethod);

        if (dangerousMethods.contains(fullMethodName)) {
            int[] compromisedParameterLocals = mapCompromisedArgumentsToParameterLocals(parameterLocals, currentArguments);
            storeAnalysisResultOnTag(parentMethod, compromisedParameterLocals);
        } else {
            analyzeInvokedMethod(parameterLocals, currentMethod, currentArguments, parentMethod);
        }
    }

    private void analyzeInvokedMethod(List<Local> parameterLocals, SootMethod invokedMethod, List<Value> args, SootMethod parentMethod) {
        boolean invokedMethodUsesParams = argListContainsParams(parameterLocals, args);

        if (invokedMethodUsesParams) {
            TaintedTag taintedTag = getOrCreateTaintedTag(invokedMethod, args.size());
            if (!taintedTag.isVisited()) {
                analyseNode(invokedMethod);
                markTagAsVisited(invokedMethod, new int[args.size()]);
            }

            taintedTag = getOrCreateTaintedTag(invokedMethod, args.size());
            int[] compromisedArguments = taintedTag.getCompromisedParamIndexes();
            updateParentTag(parameterLocals, args, parentMethod, compromisedArguments);
        }
    }

    private boolean argListContainsParams(List<Local> parameterLocals, List<Value> args) {
        return args.stream().anyMatch(arg -> parameterLocals.stream().anyMatch(param -> param.getName().equals(arg.toString())));
    }

    private int[] mapCompromisedArgumentsToParameterLocals(List<Local> parameterLocals, List<Value> currentArguments) {
        int[] compromisedParameterLocals = new int[parameterLocals.size()];
        for (Value arg : currentArguments) {
            int index = findIndex(parameterLocals, arg);

            if (index != -1) {
                compromisedParameterLocals[index] = 1;
            }
        }
        return compromisedParameterLocals;
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

    private TaintedTag storeAnalysisResultOnTag(SootMethod sootMethod, int[] compromisedIndexes) {
        TaintedTag taintedTag = getOrCreateTaintedTag(sootMethod, compromisedIndexes.length);

        taintedTag.setVisited(true);
        taintedTag.updateCompromisedParamIndexes(compromisedIndexes);
        return taintedTag;
    }

    private TaintedTag markTagAsVisited(SootMethod sootMethod, int[] compromisedIndexes) {
        TaintedTag taintedTag = getOrCreateTaintedTag(sootMethod, compromisedIndexes.length);

        taintedTag.setVisited(true);
        return taintedTag;
    }

    private TaintedTag getOrCreateTaintedTag(SootMethod sootMethod, int paramLocalSize) {
        TaintedTag taintedTag = (TaintedTag) sootMethod.getTag(TaintedTag.NAME);

        if (taintedTag == null) {
            taintedTag = new TaintedTag(new int[paramLocalSize]);
            sootMethod.addTag(taintedTag);
        }
        return taintedTag;
    }

    private int[] determineSensitiveParamIndexes(List<Local> parameterLocals) {
        if (parameterLocals.size() == 0)
            return new int[0];
        int[] indexes = new int[parameterLocals.size()];
        Arrays.fill(indexes, 1);
        return indexes;
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

    private String extractMethodName(SootMethod sootMethod) {
        return sootMethod.getDeclaringClass() + "." + sootMethod.getName();
    }

    private int findIndex(List<Local> paramLocals, Value argument) {
        for (int i = 0; i < paramLocals.size(); i++) {
            if (paramLocals.get(i).getName().equals(argument.toString())) {
                return i;
            }
        }
        return -1;
    }

    private SootMethod extractMethod(Unit unit) {
        return ((InvokeStmt) unit).getInvokeExpr().getMethod();
    }

    private List<Value> extractArguments(Unit unit) {
        return ((InvokeStmt) unit).getInvokeExpr().getArgs();
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
        TaintedTag taintedTag = (TaintedTag) sootMethod.getTag(TaintedTag.NAME);
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
//                    Tag tag = box.getTag(TaintedTag.NAME);
//                    if (tag != null) {
//                        assignStmt.getDefBoxes().get(0).addTag(tag);
//                    }
//                });
//            }
//        });
    }
}

