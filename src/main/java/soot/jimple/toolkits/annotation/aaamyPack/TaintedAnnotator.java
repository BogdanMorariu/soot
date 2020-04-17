package soot.jimple.toolkits.annotation.aaamyPack;

import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.Targets;
import soot.tagkit.Tag;
import soot.util.dot.DotGraph;

import java.util.*;
import java.util.stream.StreamSupport;

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


        int[] compromisedIndexes = analyseWithCallGraph(sootMethod);

        for (int i = 0; i < compromisedIndexes.length; i++) {
            if (compromisedIndexes[i] == 1 && sensitiveParamIndexes[i] ==1)
                System.out.println("Parameter " + parameterLocals.get(i).getName() + " was compromised");
        }
//        taintedAnalyse(sootMethod);
    }

    private int[] determineSensitiveParamIndexes(List<Local> parameterLocals) {
        if (parameterLocals.size() == 0)
            return new int[0];
        int[] indexes = new int[parameterLocals.size()];
        indexes[0] = 1;
        return indexes;
    }

    private int[] analyseWithCallGraph(SootMethod sootMethod) {
//        System.out.println(sootMethod.getName() + ": t1");

        CallGraph callGraph = Scene.v().getCallGraph();
        Body activeBody;
        try {
            activeBody = sootMethod.getActiveBody();
        } catch (Exception e) {
            //System.out.println("skipping method: " + sootMethod.getName() + ", reason: " + e.getMessage());
            return new int[0];
        }

        UnitPatchingChain units = activeBody.getUnits();
        List<Local> parameterLocals = getParameterLocals(units);
        int[] compromisedIndexes;

        if (sootMethod.getName().equals("<init>")) {
            return new int[0];
        }

        //System.out.println(sootMethod.getName() + ": t2");
        Iterator<Edge> edges = callGraph.edgesOutOf(sootMethod);
        compromisedIndexes = StreamSupport.stream(Spliterators.spliteratorUnknownSize(edges, Spliterator.ORDERED), false)
                .map(e -> {
//                    System.out.println("For method " + sootMethod.getName() + " found edge " + e.toString());
                    int[] currentCompromisedIndexes = new int[parameterLocals.size()];
                    Unit unit = e.srcUnit();
                    if (unit instanceof InvokeStmt) {// TODO pass tags at assignment
                        currentCompromisedIndexes = analyseInvokeStatement(sootMethod, parameterLocals, (InvokeStmt) unit);
                    }

                    return currentCompromisedIndexes;
//                    unit.getUseBoxes().forEach(box -> System.out.println("usebox: " + box.getValue()));
                }).reduce(new int[parameterLocals.size()], this::mergeLists);
//        Iterator<MethodOrMethodContext> ptargets = new Targets(edges);
        //System.out.println("compromisedIndexes: " + Arrays.toString(compromisedIndexes) + " -- at the end of method: " + sootMethod.getName());
        return compromisedIndexes;
    }

    private int[] mergeLists(int[] list1, int[] list2) {
        if (list1.length != list2.length) {
            throw new RuntimeException("Failed to merge lists. lengths are: " + list1.length + " and " + list2.length);
        }
        for (int i = 0; i < list1.length; i++) {
            list1[i] = list1[i] | list2[i];
        }
        return list1;
    }

    private void taintedAnalyse(SootMethod sootMethod) {
        TaintedTag taintedTag = (TaintedTag) sootMethod.getTag("pf.bm.TaintedTag");
        int[] indexes = taintedTag.getTaintedParamIndex();
        Body activeBody;
        try {
            activeBody = sootMethod.getActiveBody();
        } catch (Exception e) {
            System.out.println("skipping method: " + sootMethod.getName() + ", reasson: " + e.getMessage());
            return;
        }
        UnitPatchingChain units = activeBody.getUnits();
        List<Local> parameterLocals = getParameterLocals(units);

        units.forEach(curUnit -> {
            if (curUnit instanceof InvokeStmt) {
                analyseInvokeStatement(sootMethod, parameterLocals, (InvokeStmt) curUnit);
            } else if (curUnit instanceof AssignStmt) { //no good
                AssignStmt assignStmt = (AssignStmt) curUnit;
                List<ValueBox> useBoxes = assignStmt.getUseBoxes();
                useBoxes.forEach(box -> {
                    Tag tag = box.getTag("pf.bm.TaintedTag");
                    if (tag != null) {
                        assignStmt.getDefBoxes().get(0).addTag(tag);
                    }
                });
            }
        });
    }

    private int[] analyseInvokeStatement(SootMethod sootMethod, List<Local> parameterLocals, InvokeStmt curUnit) {
        InvokeExpr expr = curUnit.getInvokeExpr();
        SootMethod currentMethod = expr.getMethod();
        List<Value> args = expr.getArgs();
        int[] newTaintedIndexes = new int[args.size()];
        int[] returnIndexes = new int[parameterLocals.size()];

        for (int i = 0; i < args.size(); i++) {
            int index = findIndex(parameterLocals, args.get(i));
            newTaintedIndexes[i] = (index != -1) ? 1 : 0;
        }

        if (currentMethod.getName().equals("print")) { // TODO check full name here java.lang.bla
            System.out.println("Found dangerous method: " + sootMethod.getName());

            for (Value arg : args) {
                int index = findIndex(parameterLocals, arg);

                if (index != -1) {
                    returnIndexes[index] = 1;
                }
            }
            return returnIndexes;
        }

        boolean nextMethodUsesParams = args.stream().anyMatch(arg -> parameterLocals.stream().anyMatch(param -> param.getName().equals(arg.toString())));

        if (nextMethodUsesParams) {
            currentMethod.addTag(new TaintedTag(newTaintedIndexes));
            //taintedAnalyse(currentMethod);
            int[] compromisedArguments = analyseWithCallGraph(currentMethod);

            for (int i = 0; i < compromisedArguments.length; i++) {
                Value argument = args.get(i);
                //System.out.println("Method: " + currentMethod.getName() + ". Searching for argument: " + argument + " in parameter list:" + Arrays.toString(parameterLocals.toArray()));
                int paramIndex = findIndex(parameterLocals, argument);
                if(paramIndex != -1)
                    returnIndexes[paramIndex] = 1;
//                else System.out.println("SKIPPING argument: " + argument);
            }
        }
        return returnIndexes;
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

    private List<Local> getParameterLocals(UnitPatchingChain units) {
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
}

