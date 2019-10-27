import base64
import re

list_enc = ['FVJaF2IrFLAoEbRdRbupFru4FrNzFeFaFbW5RVQrGYQ=',
'EUIzE2HqEKZnDaQcQatoEqt4EqMyEdEzEaV5QUPqFXP=',
'DTHyD2GpDJYmCzPbPzsnDps4DpLxDcDyDzU5PTOpEWO=',
'CSGxC2FoCIXlByOaOyrmCor4CoKwCbCxCyT5OSNoDVN=',
'BRFwB2EnBHWkAxNzNxqlBnq4BnJvBaBwBxS5NRMnCUM=',
'AQEvA2DmAGVjZwMyMwpkAmp4AmIuAzAvAwR5MQLmBTL=',
'ZPDuZ2ClZFUiYvLxLvojZlo4ZlHtZyZuZvQ5LPKlASK=',
'YOCtY2BkYEThXuKwKuniYkn4YkGsYxYtYuP5KOJkZRJ=',
'XNBsX2AjXDSgWtJvJtmhXjm4XjFrXwXsXtO5JNIjYQI=',
'WMArW2ZiWCRfVsIuIslgWil4WiEqWvWrWsN5IMHiXPH=',
'VLZqV2YhVBQeUrHtHrkfVhk4VhDpVuVqVrM5HLGhWOG=',
'UKYpU2XgUAPdTqGsGqjeUgj4UgCoUtUpUqL5GKFgVNF=',
'TJXoT2WfTZOcSpFrFpidTfi4TfBnTsToTpK5FJEfUME=',
'SIWnS2VeSYNbRoEqEohcSeh4SeAmSrSnSoJ5EIDeTLD=',
'RHVmR2UdRXMaQnDpDngbRdg4RdZlRqRmRnI5DHCdSKC=',
'QGUlQ2TcQWLzPmCoCmfaQcf4QcYkQpQlQmH5CGBcRJB=',
'PFTkP2SbPVKyOlBnBlezPbe4PbXjPoPkPlG5BFAbQIA=',
'OESjO2RaOUJxNkAmAkdyOad4OaWiOnOjOkF5AEZaPHZ=',
'NDRiN2QzNTIwMjZlZjcxNzc4NzVhNmNiNjE5ZDYzOGY=',
'MCQhM2PyMSHvLiYkYibwMyb4MyUgMlMhMiD5YCXyNFX=',
'LBPgL2OxLRGuKhXjXhavLxa4LxTfLkLgLhC5XBWxMEW=',
'KAOfK2NwKQFtJgWiWgzuKwz4KwSeKjKfKgB5WAVwLDV=',
'JZNeJ2MvJPEsIfVhVfytJvy4JvRdJiJeJfA5VZUvKCU=',
'IYMdI2LuIODrHeUgUexsIux4IuQcIhIdIeZ5UYTuJBT=',
'HXLcH2KtHNCqGdTfTdwrHtw4HtPbHgHcHdY5TXStIAS=',
'GWKbG2JsGMBpFcSeScvqGsv4GsOaGfGbGcX5SWRsHZR=',
'FVJaF2IrFLAoEbRdRbupFru4FrNzFeFaFbW5RVQrGYQ=',
'GWKbG2JsGMBpFcSeScvqGsv4GsOaGfGbGcX5SWRsHZR=',
'HXLcH2KtHNCqGdTfTdwrHtw4HtPbHgHcHdY5TXStIAS=',
'IYMdI2LuIODrHeUgUexsIux4IuQcIhIdIeZ5UYTuJBT=',
'JZNeJ2MvJPEsIfVhVfytJvy4JvRdJiJeJfA5VZUvKCU=',
'KAOfK2NwKQFtJgWiWgzuKwz4KwSeKjKfKgB5WAVwLDV=',
'LBPgL2OxLRGuKhXjXhavLxa4LxTfLkLgLhC5XBWxMEW=',
'MCQhM2PyMSHvLiYkYibwMyb4MyUgMlMhMiD5YCXyNFX=',
'NDRiN2QzNTIwMjZlZjcxNzc4NzVhNmNiNjE5ZDYzOGY=',
'OESjO2RaOUJxNkAmAkdyOad4OaWiOnOjOkF5AEZaPHZ=',
'PFTkP2SbPVKyOlBnBlezPbe4PbXjPoPkPlG5BFAbQIA=',
'QGUlQ2TcQWLzPmCoCmfaQcf4QcYkQpQlQmH5CGBcRJB=',
'RHVmR2UdRXMaQnDpDngbRdg4RdZlRqRmRnI5DHCdSKC=',
'SIWnS2VeSYNbRoEqEohcSeh4SeAmSrSnSoJ5EIDeTLD=',
'TJXoT2WfTZOcSpFrFpidTfi4TfBnTsToTpK5FJEfUME=',
'UKYpU2XgUAPdTqGsGqjeUgj4UgCoUtUpUqL5GKFgVNF=',
'VLZqV2YhVBQeUrHtHrkfVhk4VhDpVuVqVrM5HLGhWOG=',
'WMArW2ZiWCRfVsIuIslgWil4WiEqWvWrWsN5IMHiXPH=',
'XNBsX2AjXDSgWtJvJtmhXjm4XjFrXwXsXtO5JNIjYQI=',
'YOCtY2BkYEThXuKwKuniYkn4YkGsYxYtYuP5KOJkZRJ=',
'ZPDuZ2ClZFUiYvLxLvojZlo4ZlHtZyZuZvQ5LPKlASK=',
'AQEvA2DmAGVjZwMyMwpkAmp4AmIuAzAvAwR5MQLmBTL=',
'BRFwB2EnBHWkAxNzNxqlBnq4BnJvBaBwBxS5NRMnCUM=',
'CSGxC2FoCIXlByOaOyrmCor4CoKwCbCxCyT5OSNoDVN=',
'DTHyD2GpDJYmCzPbPzsnDps4DpLxDcDyDzU5PTOpEWO=',
'EUIzE2HqEKZnDaQcQatoEqt4EqMyEdEzEaV5QUPqFXP=',
'FVJaF2IrFLAoEbRdRbupFru4FrNzFeFaFbW5RVQrGYQ=']

for i in range(0, len(list_enc)):
    try:
        res = base64.b64decode(list_enc[i])
        if not re.search('[^a-zA-Z0-9]', res):
            print 'flag{' + res + '}'
    except:
        print '[-]There is something wrong'