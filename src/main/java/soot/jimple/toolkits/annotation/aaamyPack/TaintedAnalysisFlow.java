package soot.jimple.toolkits.annotation.aaamyPack;

import soot.Unit;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ForwardFlowAnalysis;

import java.util.Collections;
import java.util.List;

public class TaintedAnalysisFlow extends ForwardFlowAnalysis<Unit, List<String>> {

    public TaintedAnalysisFlow(UnitGraph g) {
        super(g);

        doAnalysis();
    }

    @Override
    protected void flowThrough(List<String> in, Unit d, List<String> out) {

    }

    @Override
    protected List<String> newInitialFlow() {
        return Collections.emptyList();
    }

    @Override
    protected void merge(List<String> in1, List<String> in2, List<String> out) {

    }

    @Override
    protected void copy(List<String> source, List<String> dest) {

    }
}
