---- MODULE Model ----
EXTENDS Naturals

VARIABLE counter

Init == counter = 0
Next == counter' = (counter + 1) % 3
Safety == counter \in 0..2

Spec == Init /\ [][Next]_counter
====
