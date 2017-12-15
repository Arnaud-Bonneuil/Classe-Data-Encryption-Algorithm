/******************************************************************************\
fichier : Classe_Data_Encryption_Standard.h

\******************************************************************************/


#ifndef CLASSE_DATA_ENCRYPTION_STANDARD_H
#define CLASSE_DATA_ENCRYPTION_STANDARD_H

#include <stdint.h> /* uint8_t */

typedef uint8_t type_sous_clef_des[6];

typedef struct type_clef_des{
    uint8_t clef_initiale[8];
    type_sous_clef_des sous_clef_des[16];
}type_clef_des;

enum{ CHIFFREMENT, DECHIFFREMENT };

/******************************************************************************/
/* DEA_Generer_Sous_Clefs

Description :


Parametres :


Retour :
    aucun
*/
void DEA_Generer_Sous_Clefs( type_clef_des* const clef );

/******************************************************************************/
/* DEA_Afficher_Clef

Description :


Parametres :


Retour :
    aucun
*/
void DEA_Afficher_Clef( const type_clef_des* const clef );

/******************************************************************************/
/* DEA_Appliquer_Aglorithme

Description :


Parametres :


Retour :
    aucun
*/
void DEA_Appliquer_Aglorithme( const type_clef_des* const clef,
							   const uint8_t* const message,
							   uint8_t* const message_chiffre,
							   int mode );

#endif
