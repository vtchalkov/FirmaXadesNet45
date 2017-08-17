// --------------------------------------------------------------------------------------------------------------------
// XadesValidator.cs
//
// FirmaXadesNet - Librería para la generación de firmas XADES
// Copyright (C) 2016 Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena
//
// This program is free software: you can redistribute it and/or modify
// it under the +terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/. 
//
// E-Mail: informatica@gemuc.es
// 
// --------------------------------------------------------------------------------------------------------------------


using FirmaXadesNet.Signature;
using FirmaXadesNet.Utils;
using Microsoft.Xades;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections;

namespace FirmaXadesNet.Validation
{
    class XadesValidator
    {
        #region Public methods

        /// <summary>
        /// The elements that are validated are:
        /// 1.The traces of the references of the signature.
        /// 2.The trace of the SignedInfo element is verified and the signature is verified with the public key of the ///certificate.
        /// 3. If the signature contains a time stamp it is verified that the imprint of the signature coincides with that of the time stamp.
        /// The validation of profiles -C, -X, -XL and -A is outside the scope of this project.
        /// </summary>
        /// <param name="sigDocument"></param>
        /// <returns></returns>
        public ValidationResult Validate(SignatureDocument sigDocument)
        {
            ValidationResult result = new ValidationResult();

            try
            {
                // Check the traces of references and signature
                sigDocument.XadesSignature.CheckXmldsigSignature();
            }
            catch
            {
                result.IsValid = false;
                result.Message = "Signature verification is unsuccessful!";

                return result;
            }

            if (sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Count > 0)
            {
                // Check time stamp
                TimeStamp timeStamp = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection[0];
                TimeStampToken token = new TimeStampToken(new CmsSignedData(timeStamp.EncapsulatedTimeStamp.PkiData));

                byte[] tsHashValue = token.TimeStampInfo.GetMessageImprintDigest();
                Crypto.DigestMethod tsDigestMethod = Crypto.DigestMethod.GetByOid(token.TimeStampInfo.HashAlgorithm.Algorithm.Id);

                ArrayList signatureValueElementXpaths = new ArrayList
                {
                    "ds:SignatureValue"
                };
                byte[] signatureValueHash = DigestUtil.ComputeHashValue(XMLUtil.ComputeValueOfElementList(sigDocument.XadesSignature, signatureValueElementXpaths), tsDigestMethod);

                if (!Arrays.AreEqual(tsHashValue, signatureValueHash))
                {
                    result.IsValid = false;
                    result.Message = "The imprint of the time stamp does not correspond with the calculated";

                    return result;
                }
            }

            result.IsValid = true;
            result.Message = "Signature validated successfully";

            return result;
        }

        #endregion
    }
}
