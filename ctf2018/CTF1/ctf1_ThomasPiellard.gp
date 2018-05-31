criterion(p,q)=
{
    r = eulerphi(p*q);
    res = Mod(1,1337694213377816);
    for(i=1,r,
           if(gcd(i+1,r)==1,
                if(gcd(i,p-1)==2 && gcd(i,q-1)==2,
                     res = res*Mod(i+1, 1337694213377816);
                );
           );
     );
     return(lift(res));
} 
