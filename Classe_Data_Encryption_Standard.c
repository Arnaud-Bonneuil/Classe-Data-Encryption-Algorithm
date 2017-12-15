/******************************************************************************\
fichier : Classe_Data_Encryption_Standard.c
\******************************************************************************/

#include "Classe_Data_Encryption_Standard.h"

/* Inclusion des bibliotheques standard du C */
#include <stdio.h> /* printf */
#include <string.h> /* memcpy */


/******************************************************************************/
/* Constantes privees */
/******************************************************************************/
static const uint8_t MASQUE_SET[8] =
                             { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };

static const uint8_t MASQUE_RESET[8] =
                             { 0x7F, 0xBF, 0xDF, 0xEF, 0xF7, 0xFB, 0xFD, 0xFE };


static const uint8_t PC1[56] = {
    56, 48, 40, 32, 24, 16,  8,
     0, 57, 49, 41, 33, 25, 17,
     9,  1, 58, 50, 42, 34, 26,
    18, 10,  2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,
     6, 61, 53, 45, 37, 29, 21,
    13,  5, 60, 52, 44, 36, 28,
    20, 12,  4, 27, 19, 11,  3
};

static const uint8_t PC2[48] = {
    13, 16, 10, 23,  0,  4,
     2, 27, 14,  5, 20,  9,
    22, 18, 11,  3, 25,  7,
    15,  6, 26, 19, 12,  1,
    40, 51, 30, 36, 46, 54,
    29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52,
    45, 41, 49, 35, 28, 31
};

static const uint8_t IP[64] = {
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
    56, 48, 40, 32, 24, 16,  8,  0,
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6
};

static const uint8_t FP[64] = {
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
    32,  0, 40,  8, 48, 16, 56, 24
};

static const uint8_t EI[48] = {
    31,  0,  1,  2,  3,  4,
     3,  4,  5,  6,  7,  8,
     7,  8,  9, 10, 11, 12,
    11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20,
    19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28,
    27, 28, 29, 30, 31,  0
};

/* Les boites S */
static const uint8_t SI[8][4][16] = {
    /* S1 */
    {{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
     { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
     { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
     {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}},

    /* S2 */
    {{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
     {3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
     {0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
     {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}},

    /* S3 */
    {{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
     {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
     {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
     { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}},

    /* S4 */
    {{ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
     {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
     {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
     { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}},

    /* S5 */
    {{ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
     {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
     { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
     {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}},

    /* S6 */
    {{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
     {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
     { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
     { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}},

    /* S7 */
    {{ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
     {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
     { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
     { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}},

    /* S8 */
    {{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
     { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
     { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
     { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}}
};

static const uint8_t P[32] = {
    15,  6, 19, 20,
    28, 11, 27, 16,
     0, 14, 22, 25,
     4, 17, 30,  9,
     1,  7, 23, 13,
    31, 26,  2,  8,
    18, 12, 29,  5,
    21, 10,  3, 24
};


/******************************************************************************/
/* Declaration des fonctions privees */
/******************************************************************************/
/* Afficher_Bloc_Hexa

Description :
    Affiche en hexadecimale dans la console la valeur de tous les elements 
    d'un tableau de uint_8.
    Il n'y a pas d'espace entre les valeurs des elements du tableau.
    Chaque valeur du tableau est representee par deux chiffres (0 compris).
    Ajoute un retour a la ligne apres la valeur du dernier element du tableau.

Parametres :
    bloc : pointeur constant sur un tableau constant de uint8_t
    taille : nombre d'octets du tableau

Retour :
    aucun
*/
static void Afficher_Bloc_Hexa( const uint8_t* const bloc, uint8_t taille );

/******************************************************************************/
/* Set_Bit_Bloc

Description :
    Valorise a 1 un bit dans un tableau de uint8_t

Parametres :
    bloc : pointeur constant sur un tableau de uint8_t
    indice_bit : numero du bit a valoriser a 1, le bit 0 est le bit de poids 
                 fort du premier octet du tableau

Retour :
    aucun
*/
static void Set_Bit_Bloc( uint8_t* const bloc, uint8_t indice_bit );

/******************************************************************************/
/* Reset_Bit_Bloc

Description :
    Valorise a 0 un bit dans un tableau de uint8_t

Parametres :
    bloc : pointeur constant sur un tableau de uint8_t
    indice_bit : numero du bit a valoriser a 0, le bit 0 est le bit de poids 
                 fort du premier octet du tableau

Retour :
    aucun
*/
static void Reset_Bit_Bloc( uint8_t* const bloc, uint8_t indice_bit );

/******************************************************************************/
/* Tester_Bit_Bloc

Description :
    Teste la valeur d'un bit dans un tableau de uint8_t.

Parametres :
    bloc : pointeur constant sur un tableau constant de uint8_t
    indice_bit : numero du bit a tester, le bit 0 est le bit de poids fort du
                 premier octet du tableau

Retour :
    1 si le bit teste vaut 1, 0 sinon
*/
static int Tester_Bit_Bloc( const uint8_t* const bloc, uint8_t indice_bit );

/******************************************************************************/
/* Permuter_Bits

Description :


Parametres :
     bloc_initial : pointeur constant sur un tableau constant de uint8_t
     taille_bloc : nombre de bits du tableau de resultat
     resultat : pointeur constant sur un tableau de uint8_t resultat de
                la permutation
     table_permutation : pointeur constant sur un tableau constant de uint8_t

Retour :
    aucun
*/
static void Permuter_Bits( const uint8_t* const bloc_initial,
                           uint8_t taille_bloc,
                           uint8_t* const resultat,
                           const uint8_t* const table_permutation );

/******************************************************************************/
/* Decaler_Bits_Gauche_Par_Moitie

Description :


Parametres :


Retour :
    aucun
*/
static void Decaler_Bits_Gauche_Par_Moitie( uint8_t* const bloc );


/******************************************************************************/
/* Definition des methodes publiques */
/******************************************************************************/
void DEA_Afficher_Clef( const type_clef_des* const clef )
{
    int id_clef = 0;

    Afficher_Bloc_Hexa( clef->clef_initiale, 8 );
    for( id_clef=0 ; id_clef<=15 ; id_clef++ )
    {
        Afficher_Bloc_Hexa( (clef->sous_clef_des)[id_clef], 6 );
    }
}
/******************************************************************************/
void DEA_Generer_Sous_Clefs( type_clef_des* const clef )
{
    uint8_t bloc_56_bits[7] = {0};
    int id_clef = 0;

    Permuter_Bits( clef->clef_initiale, 56, bloc_56_bits, PC1 );
    for( id_clef=0 ; id_clef<=15 ; id_clef++ )
    {
        if( id_clef==0 || id_clef==1 || id_clef==8 || id_clef==15 )
        {
            /* une seule rotation à gauche */
            Decaler_Bits_Gauche_Par_Moitie( bloc_56_bits );
        }
        else
        {
            /* deux rotations à gauche */
            Decaler_Bits_Gauche_Par_Moitie( bloc_56_bits );
            Decaler_Bits_Gauche_Par_Moitie( bloc_56_bits );
        }
        Permuter_Bits( bloc_56_bits, 48, (clef->sous_clef_des)[id_clef], PC2 );
    }
}
/******************************************************************************/
void DEA_Appliquer_Aglorithme( const type_clef_des* const clef,
                               const uint8_t* const message,
                               uint8_t* const message_chiffre,
                               int mode )
{
    uint8_t copie_message[8] = {0};
    uint8_t* gauche = NULL;
    uint8_t* droite = NULL;
    uint8_t drt_copie[4] = {0};
    uint8_t drt_tmp[4] = {0};
    uint8_t drt_exp[6] = {0};
    uint8_t valeur_boite = 0;
    int ronde = 0;
    int id_octet = 0;
    uint8_t id_boite = 0;
    int b_0, b_1, b_2, b_3, b_4, b_5;
    int ligne, colonne;

    memcpy( copie_message, message, 8 );

    /* Permutation initiale */
    Permuter_Bits( message, 64, copie_message, IP );

    /* Separation en deux blocs Gauche et Droite */
    gauche = copie_message;
    droite = &(copie_message[4]);

    /* Copie du bloc de droite */
    memcpy( drt_copie, droite, 4 );

    for( ronde=0 ; ronde<=15 ; ronde++ )
    {
        /* Expansion du bloc de droite */
        Permuter_Bits( droite, 48, drt_exp, EI );

        if( mode==CHIFFREMENT )
        {
            for( id_octet=0 ; id_octet<6 ; id_octet++ )
            {
                drt_exp[id_octet]^=((clef->sous_clef_des)[ronde][id_octet]);
            }
        }
        else if( mode==DECHIFFREMENT )
        {
            for( id_octet=0 ; id_octet<6 ; id_octet++ )
            {
                drt_exp[id_octet]^=((clef->sous_clef_des)[15-ronde][id_octet]);
            }
        }
        else
        {
            /* erreur */
        }

        /* Fonctions de selection */
        memset( drt_tmp, 0, 4 );
        for( id_boite=0 ; id_boite <=7 ; id_boite++ )
        {
            uint8_t decalage;
            decalage = 6*id_boite;
            b_0 = Tester_Bit_Bloc( drt_exp, 0 + decalage );
            b_1 = Tester_Bit_Bloc( drt_exp, 1 + decalage );
            b_2 = Tester_Bit_Bloc( drt_exp, 2 + decalage );
            b_3 = Tester_Bit_Bloc( drt_exp, 3 + decalage );
            b_4 = Tester_Bit_Bloc( drt_exp, 4 + decalage );
            b_5 = Tester_Bit_Bloc( drt_exp, 5 + decalage );
            ligne = b_0*2 + b_5;
            colonne = b_1*8 + b_2*4 + b_3*2 + b_4;
            valeur_boite = SI[id_boite][ligne][colonne];
            decalage = 4*id_boite;
            if( (valeur_boite&0x08) )
            {
                Set_Bit_Bloc( drt_tmp, 0 + decalage );
            }
            if( (valeur_boite&0x04) )
            {
                Set_Bit_Bloc( drt_tmp, 1 + decalage );
            }
            if( (valeur_boite&0x02) )
            {
                Set_Bit_Bloc( drt_tmp, 2 + decalage );
            }
            if( (valeur_boite&0x01) )
            {
                Set_Bit_Bloc( drt_tmp, 3 + decalage );
            }
        }

        /* Permutation */
        Permuter_Bits( drt_tmp, 32, droite, P );

        for( id_octet=0 ; id_octet<=3 ; id_octet++ )
        {
            droite[id_octet] ^= gauche[id_octet];
            gauche[id_octet] = drt_copie[id_octet];
            drt_copie[id_octet] = droite[id_octet];
        }
    }
    /* Permutation finale (initiale inverse) */
    memcpy( droite, gauche, 4);
    memcpy( gauche, drt_copie, 4);
    Permuter_Bits( copie_message, 64, message_chiffre, FP );
}
/******************************************************************************/


/******************************************************************************/
/* Definition des fonctions privées */
/******************************************************************************/
static void Afficher_Bloc_Hexa( const uint8_t* const bloc, uint8_t taille )
{
    uint8_t indice_octet = 0;
    for( indice_octet = 0; indice_octet<taille ; indice_octet++ )
    {
        printf( "%02X", bloc[indice_octet] );
    }
    printf( "\n" );
}
/******************************************************************************/
static void Set_Bit_Bloc( uint8_t* const bloc, uint8_t indice_bit )
{
    bloc[indice_bit/8] |= MASQUE_SET[indice_bit%8];
}
/******************************************************************************/
static void Reset_Bit_Bloc( uint8_t* const bloc, uint8_t indice_bit )
{
    bloc[indice_bit/8] &= MASQUE_RESET[indice_bit%8];
}
/******************************************************************************/
static int Tester_Bit_Bloc( const uint8_t* const bloc, uint8_t indice_bit )
{
    return ( ( bloc[indice_bit/8] & MASQUE_SET[indice_bit%8] ) != 0 ) ? 1 : 0;
}
/******************************************************************************/
static void Decaler_Bits_Gauche_Par_Moitie( uint8_t* const bloc_56_bit )
{
    int bit_0 = 0;
    int bit_28 = 0;
    uint8_t indice_bit = 0;

    bit_0 = Tester_Bit_Bloc( bloc_56_bit, 0 );
    bit_28 = Tester_Bit_Bloc( bloc_56_bit, 28 );

    for( indice_bit = 0; indice_bit<=54 ; indice_bit++ )
    {
        if( Tester_Bit_Bloc( bloc_56_bit, indice_bit+1 ) )
        {
            Set_Bit_Bloc( bloc_56_bit, indice_bit );
        }
        else
        {
            Reset_Bit_Bloc( bloc_56_bit, indice_bit );
        }
    }
    if( bit_0 )
    {
        Set_Bit_Bloc( bloc_56_bit, 27 );
    }
    else
    {
        Reset_Bit_Bloc( bloc_56_bit, 27 );
    }
    if( bit_28 )
    {
        Set_Bit_Bloc( bloc_56_bit, 55 );
    }
    else
    {
        Reset_Bit_Bloc( bloc_56_bit, 55 );
    }
}
/******************************************************************************/
static void Permuter_Bits( const uint8_t* const bloc_initial,
                           uint8_t taille_bloc,
                           uint8_t* const resultat,
                           const uint8_t* const table_permutation )
{
    uint8_t id_bit = 0;
    for ( id_bit=0 ; id_bit<taille_bloc ; id_bit++ )
    {
        if( Tester_Bit_Bloc( bloc_initial, table_permutation[id_bit] ) )
        {
            Set_Bit_Bloc( resultat, id_bit );
        }
        else
        {
            Reset_Bit_Bloc( resultat, id_bit );
        }
    }
}
/******************************************************************************/
