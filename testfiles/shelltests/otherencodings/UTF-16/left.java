p u b l i c   c l a s s   T e s t   { 
 
                 p u b l i c   d o u b l e   s c a l a r P r o d u c t ( P o i n t   u ,   P o i n t   v )   { 
                                 r e t u r n   u . x   *   v . x   +   u . y   *   v . y   +   u . z   *   v . z ; 
                 } 
 
                 p u b l i c   P o i n t   n o r m a l i z e ( P o i n t   u )   { 
                                 r e t u r n   u . m u l t i p l y ( 1 / t h i s . s c a l a r P r o d u c t ( u , u ) ) ; 
                 } 
 } 
 
 