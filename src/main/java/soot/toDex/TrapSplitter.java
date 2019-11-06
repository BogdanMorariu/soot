package soot.toDex;

/*-
 * #%L
 * Soot - a J*va Optimization Framework
 * %%
 * Copyright (C) 1997 - 2018 Raja Vallée-Rai and others
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 * 
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>.
 * #L%
 */

import java.util.Map;
import java.util.Set;

import soot.Body;
import soot.BodyTransformer;
import soot.Singletons;
import soot.Trap;
import soot.Unit;
import soot.jimple.Jimple;
import soot.util.HashMultiMap;
import soot.util.MultiMap;

/**
 * Transformer that splits nested traps for Dalvik which does not support hierarchies of traps. If we have a trap (1-3) with
 * handler A and a trap (2) with handler B, we transform them into three new traps: (1) and (3) with A, (2) with A+B.
 *
 * @author Steven Arzt
 */
public class TrapSplitter extends BodyTransformer {

  public TrapSplitter(Singletons.Global g) {
  }

  public static TrapSplitter v() {
    return soot.G.v().soot_toDex_TrapSplitter();
  }

  private class TrapOverlap {
    private Trap t1;
    private Trap t2;
    private Unit t2Start;

    public TrapOverlap(Trap t1, Trap t2, Unit t2Start) {
      this.t1 = t1;
      this.t2 = t2;
      this.t2Start = t2Start;
    }
  }

  @Override
  protected void internalTransform(Body b, String phaseName, Map<String, String> options) {
    // If we have less then two traps, there's nothing to do here
    if (b.getTraps().size() < 2) {
      return;
    }

    // Look for overlapping traps
    TrapOverlap to;
    while ((to = getNextOverlap(b)) != null) {
      // If one of the two traps is empty, we remove it
      if (to.t1.getBeginUnit() == to.t1.getEndUnit()) {
        b.getTraps().remove(to.t1);
        continue;
      }
      if (to.t2.getBeginUnit() == to.t2.getEndUnit()) {
        b.getTraps().remove(to.t2);
        continue;
      }

      // t1start..t2start -> t1'start...t1'end,t2start...
      if (to.t1.getBeginUnit() != to.t2Start) {
        // We need to split off t1.start - predOf(t2.splitUnit). If both traps
        // start at the same statement, this range is empty, so we have checked
        // that.
        Trap newTrap = Jimple.v().newTrap(to.t1.getException(), to.t1.getBeginUnit(), to.t2Start, to.t1.getHandlerUnit());
        safeAddTrap(b, newTrap, to.t1);
        to.t1.setBeginUnit(to.t2Start);
      }
      // (t1start, t2start) ... t1end ... t2end
      else if (to.t1.getBeginUnit() == to.t2.getBeginUnit()) {
        Unit firstEndUnit = to.t1.getBeginUnit();
        while (firstEndUnit != to.t1.getEndUnit() && firstEndUnit != to.t2.getEndUnit()) {
          firstEndUnit = b.getUnits().getSuccOf(firstEndUnit);
        }

        if (firstEndUnit == to.t1.getEndUnit()) {
          if (to.t1.getException() != to.t2.getException()) {
            Trap newTrap
                = Jimple.v().newTrap(to.t2.getException(), to.t1.getBeginUnit(), firstEndUnit, to.t2.getHandlerUnit());
            safeAddTrap(b, newTrap, to.t2);
          } else if (to.t1.getHandlerUnit() != to.t2.getHandlerUnit()) {
            // Traps t1 and t2 catch the same exception, but have different handlers
            //
            // The JVM specification (2.10 Exceptions) says:
            // "At run time, when an exception is thrown, the Java
            // Virtual Machine searches the exception handlers of the current method in the order
            // that they appear in the corresponding exception handler table in the class file,
            // starting from the beginning of that table. Note that the Java Virtual Machine does
            // not enforce nesting of or any ordering of the exception table entries of a method.
            // The exception handling semantics of the Java programming language are implemented
            // only through cooperation with the compiler (3.12)."
            //
            // 3.12
            // "The nesting of catch clauses is represented only in the exception table. The Java
            // Virtual Machine does not enforce nesting of or any ordering of the exception table
            // entries (2.10). However, because try-catch constructs are structured, a compiler
            // can always order the entries of the exception handler table such that, for any thrown
            // exception and any program counter value in that method, the first exception handler
            // that matches the thrown exception corresponds to the innermost matching catch clause."
            //
            // t1 is first, so it stays the same.
            // t2 is reduced
            Trap newTrap
                = Jimple.v().newTrap(to.t1.getException(), to.t1.getBeginUnit(), firstEndUnit, to.t1.getHandlerUnit());
            safeAddTrap(b, newTrap, to.t1);
          }
          to.t2.setBeginUnit(firstEndUnit);
        } else if (firstEndUnit == to.t2.getEndUnit()) {
          if (to.t1.getException() != to.t2.getException()) {
            Trap newTrap2
                = Jimple.v().newTrap(to.t1.getException(), to.t1.getBeginUnit(), firstEndUnit, to.t1.getHandlerUnit());
            safeAddTrap(b, newTrap2, to.t1);
            to.t1.setBeginUnit(firstEndUnit);
          } else if (to.t1.getHandlerUnit() != to.t2.getHandlerUnit()) {
            // If t2 ends first, t2 is useless.
            b.getTraps().remove(to.t2);
          } else {
            to.t1.setBeginUnit(firstEndUnit);
          }
        }
      }
    }
  }

  /**
   * Adds a new trap to the given body only if the given trap is not empty
   *
   * @param b
   *          The body to which to add the trap
   * @param newTrap
   *          The trap to add
   * @param position
   *          The position after which to insert the trap
   */
  private void safeAddTrap(Body b, Trap newTrap, Trap position) {
    // Do not create any empty traps
    if (newTrap.getBeginUnit() != newTrap.getEndUnit()) {
      if (position != null) {
        b.getTraps().insertAfter(newTrap, position);
      } else {
        b.getTraps().add(newTrap);
      }
    }
  }

  /**
   * Gets two arbitrary overlapping traps in the given method body
   *
   * @param b
   *          The body in which to look for overlapping traps
   * @return Two overlapping traps if they exist, otherwise null
   */
  protected TrapOverlap getNextOverlap(Body b) {
    Map<Unit, Integer> unitMap = createUnitNumbers(b);
    MultiMap<Unit, Trap> trapsPerUnit = new HashMultiMap<>();
    for (Trap t : b.getTraps()) {
      for (Unit unit = t.getBeginUnit(); unit != t.getEndUnit(); unit = b.getUnits().getSuccOf(unit)) {
        Set<Trap> existingTraps = trapsPerUnit.get(unit);
        for (Trap e : existingTraps) {
          if (e != t && (e.getEndUnit() != t.getEndUnit() || e.getException() == t.getException())) {
            Trap t1, t2;
            if (trapStartsBefore(unitMap, t, e)) {
              t1 = t;
              t2 = e;
            } else {
              t1 = e;
              t2 = t;
            }
            if (t1.getBeginUnit() == unit && t2.getEndUnit() != unit) {
              return new TrapOverlap(t1, t2, e.getBeginUnit());
            }
          }
        }
        trapsPerUnit.put(unit, t);
      }
    }

    return null;
  }

  /**
   * Create a map of units to integer, denoting the index of an unit
   *
   * @param b
   *          the body
   * @return the map
   */
  protected Map<Unit, Integer> createUnitNumbers(Body b) {
    int idx = 0;
    Map<Unit, Integer> res = new HashMap<Unit, Integer>();
    for (Unit u : b.getUnits()) {
      res.put(u, idx++);
    }
    return res;
  }

  /**
   * Returns true when a comes before b according to the unit map
   *
   * @param unitMap
   *          the unit map
   * @param a
   * @param b
   * @return true when a comes before b according to the unit map
   */
  protected boolean trapStartsBefore(Map<Unit, Integer> unitMap, Trap a, Trap b) {
    return unitMap.get(a.getBeginUnit()) < unitMap.get(b.getBeginUnit());
  }

}
