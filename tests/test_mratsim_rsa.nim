import crunchy/mratsim, std/strutils

import
  constantine/math/arithmetic/limbs_unsaturated, # TODO: move SignedSecretWord to constantine/platforms/constant_time
  constantine/math/arithmetic/[bigints, bigints_montgomery, limbs_montgomery],
  constantine/math/config/precompute,
  constantine/math/io/io_bigints,
  constantine/platforms/abstractions,
  constantine/hashes

from std/base64 import nil

# block:
#   var pk: RsaPrivateKey
#   pk.kind = k1024
#   pk.n = initBigInt(5)
#   pk.d = initBigInt(5)
#   pk.p = initBigInt(5)
#   pk.q = initBigInt(5)
#   pk.e1 = initBigInt(5)
#   pk.e2 = initBigInt(5)
#   pk.coef = initBigInt(5)

#   discard pk.sign_SHA256("test")

# block:
#   let pk1024 = decodePrivateKey(readFile("tests/data/1024.txt"))
#   # doAssert pk1024.size == 1024
#   # doAssert pk1024.n.toString(16).toUpperAscii() ==
#   #   "DD7273A9F583D5521CC4CE452C1F950A6009D18E106BB226D90180217416F6674DE2AC967AD8C62F6BB3311752B359756CFE7D039C2BD13BE5BC6A552FC1D33FD2DF241662A6FF93F40C9E5B23D364457B4ABE1B55E7235837A56CFAEB86AD0D203A3AB84B429EE121F5892C09A37B6E7AE2975E10FD42CD1B4AD3C9A7843B21"
#   # doAssert pk1024.e.toString(16).toUpperAscii() ==
#   #   "10001"
#   # doAssert pk1024.d.toString(16).toUpperAscii() ==
#   #   "6C09F8D044CE2AF742BDE9FCE9880708E6CE2384F211F8FAE708CA6087E8E41286773EC8B3EAAAD65BEF32D6342CF84A4800E93127B261049E130CB5BEF50B80C114304799A28E0E57B497396DDD92726FE0F28B967484A390FEDE5C7DE401A07CC435B79E9A08983D45B9CF48C6B096EF0D9FE08AD6C1F3CD62B0B2A7540621"
#   # doAssert pk1024.p.toString(16).toUpperAscii() ==
#   #   "FF68F9CF47BCCB5B9CB3512254A9FA456E574998A26B9A629ABA79A77B527E14A1E852D0148E61D611FE131CC9886BEF9781C46B878A0389FA8AA71AB904FC65"
#   # doAssert pk1024.q.toString(16).toUpperAscii() ==
#   #   "DDF564C664AB67474469FAD19CD743CB07663FBE4F3D820254891588EB73B6012326FCB59810E1518964C1DF82CCD37744D434D14DDF12888CB4DA491EE6220D"
#   # doAssert pk1024.e1.toString(16).toUpperAscii() ==
#   #   "5EB4A134C007FC6BEAEDFEDEB90012421E89154C18A5C7A85A715CDCC278B331995B9921790DD6AF571A9C21A7850368E308063A4D16DAFB15C0C5F7BDB56095"
#   # doAssert pk1024.e2.toString(16).toUpperAscii() ==
#   #   "3CA4B97E032F59AE7D20BFA8D9C36F005FEB2DEB5F571CD86A24723FD0A4F2CB68C15436816FCB402DDBDBA4A7E632B8D9936942EE95CE4884B93D12D1606B59"
#   # doAssert pk1024.coef.toString(16).toUpperAscii() ==
#   #   "4B7D86348701973C63EF0E238F649DBE6552F8564FE762002A7C5EB1D0FCE16A775FB869FDDB83160665E9F686A48FB120C2A419E2867666C61F706AA08AFDB5"

#   let message = "test message\n"
#   let sig = pk1024.sign_SHA256(message)
#   var signature = base64.encode(sig, safe = true)
#   echo signature
#   doAssert pk1024.sign_SHA256("test message\n").toHex().toUpperAscii() ==
#     "4CD7C03D5AF5423761CF367A998E4E793C08665F86BE895096112F15A387961CF6FAF4AA2171C4850E14782E7D54664829D6B9FB66620E10B5856662B1E052F180588AD9DF7A882FEC8FF71325F1F70017B21278DC3FB18754C7463C477389BD6F80CDAA942864267C21C495EEB7B3EEE4C1CAE2C9CE5FAF816657D6BE632228"

block:
  let pk2048 = decodePrivateKey(readFile("tests/data/2048.txt"))
  # doAssert pk2048.size == 2048
  # doAssert pk2048.n.toString(16).toUpperAscii() ==
  #   "A776AE49485CB50AF334CA70D70A19EAC1B954BF0854DD3496F5C6786185B008F6482CD5054DB2E4D24E8A54B0C3CA11D89BB5C6206286A668901739C06A699FD9F02103A761A6BBD7BAEF8D42894FF979E4BCF50066300AEA3D561B367AF3BD5B1EF9BB24F774138A693878DEA2796B3FDA746B1F491AE91E8979E7CC014CB174BACF4F5E53E75FBD066783E5EAAEF7B0EF760F4E32834BE81CD92024B9AA394D3A519AD7C636215559BE2DA1ACEF94E41C84C4F033AF4F293B450D313220EA9B6EAAE508238C3A6E1644109D7BEDB5AF68113101843A3607C20A5C76B6D7865BECC8D58DB79F805A8F3D86589D08AEEE936FE8C216D1651513BFD3ED09CBE7"
  # doAssert pk2048.e.toString(16).toUpperAscii() ==
  #   "10001"
  # doAssert pk2048.d.toString(16).toUpperAscii() ==
  #   "24373157DDD356BFC87AE930E0006A3C6FAAC1DE1252300878812C6BCA435C1F840B75CE97B806F11F5E26E24BDBFBAE4256E247B7A7371173D97D7C5AD568844E6074F3525676F576A111BF4DDD5E33489E24132403F56DD6DC6EEBB1AB835CB7010AE6E306B4CEA9073A54416987B29EFB8263CC3F461796280AFA0B0F58E34A154523ED6BE86C0F315166A575D1CEFD7D685D6F10252CF6F36D0AAFAF9DC938012EC48B713C88277CEE5481444F6F69B304E2DBE9DD15170684244A811EE491AF737DDCC5E7B7C8CF3B82B2A5AC8042162F6F676DDB9E8AF9BAF61EF8C2C46946588E17F19460BC769566343F0A3A8B3C9B04F8EF445C384205F846922FB9"
  # doAssert pk2048.p.toString(16).toUpperAscii() ==
  #   "D353752575AF4E3F54BE064EC47968F9A129018D87C8188F23D1161F88B006D9215BFB60634D31DD6C8B7CDE6E4CCE2D7B8DFFF6542DC44FA9DB24E4C95F22D111D88449E52D0C62258EDB05011FE4AE5251C8D632902DE9E638F222BE1BE474C80FE22B0AC7333106F64A448B253C0A1BBDC1B765ED5A0AAAC230A4BFC5530D"
  # doAssert pk2048.q.toString(16).toUpperAscii() ==
  #   "CADD7A1CDB83B58A1DBB5F7E03F01F2016048540F58323E4EADED3AC0BB673A8511B2CEC9EABB356914F30495FAFAA44C318A67A50B9BAF87CC377673BBE854463AC463111974873E680DDAD1F77F50D87C7604B830CC6558344504FF0704A6136E6474F85872AC15BAA66AE2A80E991C6FBA4A9D67A1C2A31FECAF29F1B6DC3"
  # doAssert pk2048.e1.toString(16).toUpperAscii() ==
  #   "2B5EB36A0EAEFDB60DA43A132C4B6679E4D34F9846479092BFDD07574D6C22DBA8F701AE1473214ABA1E1E705FDEAF69B233C056438C68FF98727B2DE10DFF4D3D065C8FF5D2BAF9E18F61EFB2FD62A74C09B0D814E47627CCB1DF2FB6286F48704EA23207323E954F4278977C9F15A555702A33835DA4DF0F906EFF40C43479"
  # doAssert pk2048.e2.toString(16).toUpperAscii() ==
  #   "79DA009036D66D03D20A0B38C11AC94757924D8C102C3E323155B8A4FDC010C688391F89DD60DAEEE3874244C061DE8F40F49C8299DC85CEDDF9F6CD9E5838EA3448753CE20911AEF44471629CA54C1F5D704789F3E4877933C8A3C8F06E326F242FBBA3AB5BDE35985EC920524D6E7E6E9C1673216DE55EFEFAC1626C69684B"
  # doAssert pk2048.coef.toString(16).toUpperAscii() ==
  #   "B97EBC205F45F368F37189282F0577C83F2B178C5FCA067EB7CAEA3E2D5CF64FA8538DF2A88198D54818EF10091544459BE38B46EF138962BA46DD1544F643A34CBDA283D1AFBF28BF1E5EF5B068FD9AD1D11B86705A54081582B78097FB69ED78584C439203704BCC5FD7F88539939ACE3DC9FD819C583514F869F9DE42F75"

  echo pk2048.sign_SHA256("test message\n").toHex()[2..^1].toUpperAscii()

  doAssert pk2048.sign_SHA256("test message\n").toHex()[2..^1].toUpperAscii() ==
    "A5F43E045C98AB984080614C6D8A996397352795185292D8AC9985E0AA4786A003CEA89A3DB38F8E2A8890A6D6198E6CEC88286DA451BF532CAF3C83C90597F4FF1C61933CEC6C2C7246EC13B1884EFE133505E5295AC35D49E9ED8C96444362AF4EB5D85B3388FD0597CB108C6BA3D980B299FBAEAFD3F2E15CF8379DD83A516A3E7EE0ABBB4F040B999C9549D7250365ED79B1A9EBD266B7EBF1209364791E34722CFFE21805D6F0C60AFFE993AC3ED335FD1DA89ACAB9E0F02511560D3DC0C92641B7C0532CA4F5845BA1FD6177E796A8DC14BC1BEB9D33D0232D60329A16C6D2716898F4D318538EB281792C1C4A8371034A136ED829E5F0FF10AF947330"

# block:
#   let pk4096 = decodePrivateKey(readFile("tests/data/4096.txt"))
#   doAssert pk4096.size == 4096
#   doAssert pk4096.n.toString(16).toUpperAscii() ==
#     "C866DBBBBDB1FD3FAF403EDEE646F5BD0448540D0D577C8076D989AC6465798EF64EE92D3FCAA3D47FEB68604312324E096CF7A8677C007645FF46CDC7BD897076FACD5C1A8B8FCA38001834380084B4420F46C9FFDAD48E6F55293E73D83B8CAA2BC9635097318FDACF7EB2B40A9568E8A37EBA0CFDE5D1596D87111696C3B17E95A5A2CB7526801D36971A664D508C51C4BFA0D961C2B6923A7C3B2BABD9DC302FBC6C7068262325625B0D1C312F9CD30C7B4B0B012C9486364AB707B07DAC23A0173CED9770C06C1F211C6EAEB649F62C3D033A8EE0DE564510C0D0E7E9B1871ADE34AF64BBDD1A971362858BCB74C03F23F72C1F762C9F6BE28FEF650ED4971E5C26DF2F4D874B3DC0323542D8F052D2F64039DA7CB1A09B530C1649CA890E3F5D62B9B3DDE65DC69152530CB0605783447D0A03A01577B84DFB4C264AF1A7B0F883A8DA2A009315CD9D032645F7734E9E19CC847396CDC41F03F93C8841A848BCE6C778764393C292940B10ADDCC30E1C27DBF7D6772F4D978812856CB830D9C2ABB13A0BAEBA1C10938EB33C246D37B4F39245C63BD22B4A502D8605EA716FF8D3A246D1352254AE8D5EFAE87F8CA362088AF2F7F7ABAFA635B414587F2DCD1F7DB5469A89C2D767AF375F1CFCCE327F036436F960FA0BDA6C9AF219E4C44698D1B1E1FD4B605B65C8981627087661BFF202136B6CB2D1DDB6ADE7921D"
#   doAssert pk4096.e.toString(16).toUpperAscii() ==
#     "10001"
#   doAssert pk4096.d.toString(16).toUpperAscii() ==
#     "CB943204366069F418041BDA33F4420F121AA7C7DA95D5546B67F203BEB99713340455BC31E1992C76069EB1AB7100C965A9DCACA6F3C14465373EA62D12CE5C018226BC39FB2CC730BC67DA2449E2857BD629036B76D2171FE25353AE3B2BC369DBB169C2A4D5245E140B915E74A1F340E1560B8AC7227FD968FA9CD165B6C6C8E11CB2941D1E4F675DDD82640A86990537E9B36D2172BC253064A37769CC97721C0C3DDCB2F08B239F16FFEA73CCFA732B6AD481096050414745FF4940716A3D869414C107E6F292E3CCAF2581368D4C1704A41308B2472B3C5E18822015B6D298E8C27CAAC86D846594BBB10EA250A83B7C3DCC04E9F7CABBBE1C9A04FF5A0AAC7D575BC7225E5EA412C65BA0CE398149A92BC537BA79943C99523C0C01670CC6B74F9F3ECAED4843EC5300BA1043489A637A228D470C7BDE7DDDB1ED5161674D8F42500DE2E59B31ECEB07392D85030F3BBDEBC8532BDC9BE4551A6ED73922E2FF4107A17012A7A5C72D23A4A713A56E03209BFDBBF9B7CFDC3E9BDA1E7C70E76AA31D39878B93B426D881F48931B85FE6AEBC6009D1D2BADA7145978A26304EB4EE26ADE99A042A25C9B8A6059F2785288DE9706F3B0CEC474979C135D2D890DEF0A69FA362F855C4420A2564CBB969EC728ACD3624D76FC8712EADA5EE4D30B1F32153631AF9DC29D4429CFBE96A884C4887E484370C34ABA7652F2BD"
#   doAssert pk4096.p.toString(16).toUpperAscii() ==
#     "EDD8B9AAF05F871B9ADD795BA7E1BC9FA1FC5D5FF0DBC4EDE4DF73FE240F3E28A7F3122D67457DED914FE3657269DE5A66966D38CD92203F3FCB254D3D6547A97F9276E7DAE650EDB7A0B542CE8419B4DC543326434610B6E982DB825E57AA0CE36E69134CB89CA7DCCA751EDC71EAD8AF7A275C29B58F1B2510EDA96373A6739A12242D0A271931DE5331468FE5A8E9C43E9196CFB294D1B760EDF2A958A7E2240A2A50F477B4F218C58715D99E97A204980B33BA1E20C25E3CE876359BB89E20AA300870C61EE66153CB334E8C5B40FCD4E0C98DA0BE54F9A2E0CE7575519B316E27518A7F3E4A244B498AB9A6AB338455DB2142BFF8875E6D4CA879967843"
#   doAssert pk4096.q.toString(16).toUpperAscii() ==
#     "D7B280335C839DABBB31E1E62F7777A36166273893EAD8CC3A82A9E70AE80E0E84C2C5CCF3E017D1D78880ECC409EE26547ABAC38162051EFD600C3588970A7C2C1F47E65FB38B5B17E7FD7A6D96969479BCF5D2390DE8DB66B78231EFC8118C377C7EE08EBC30C5856903F9C91966155108A23C78FC9A730907FBD345569468952A51FAF634D4134D5BC00F40D44CC2AECFCC40044976BE970500F4BDCA7FF0D254DE168986732A113BD016A08E185DE17BAE5E2100CBF77C6C929909A87DD7467655269E72C94563A2435E235D7F2926FC245C72BC202734517936D2209A2903FDCAA239B1D9385F1A9DDED4183FB2D62B6DE310BBAF544156434E004DD61F"
#   doAssert pk4096.e1.toString(16).toUpperAscii() ==
#     "4D1CF71574D983F46F415F175856D7D0E9B3E89232850E5412E05FBB05F5EB3143428BA22CD95AFAAB223B97A880AA96A4AC20BD49E9168B6B2371F498F33D48B713C579667F45BDCCCB4DF95AFB795A2A152280454F721BDB999191B304B91D749F5771EA6DF05C7C3927BFD9B9156B2B796F49723C6B2961DB1B32D00BAEEBCC0815B2849828930281F677EA2F8B943F0C0A27DB2F0B10F36379C233258B48C6668551B9F115B9684EA27D7310F8188F64BC3D091ABB8449097654DD0C9FCEA4C888CA33C6083EA94F819220E560B0B148539905521863748C5A5695BE73B6DD4FD96F9677AABA5F0A09CDF063191E9AC93B428D61B032336B3C6F62FC6601"
#   doAssert pk4096.e2.toString(16).toUpperAscii() ==
#     "7833C771D7FA98E15CFE9D6F13C0B5F15C93FB03729B0B9A34792089DAF01AF54852EABC1EA421621584C2A42F53815DE6F246263172187C7EA309EAC365B8B81E368870FFA024E6ECD9A1CE9A47B33EA6E100F4D84AC21B92906D83BAA679F0F3F2F319DD314ED4A456339AFDD0A3ACF96DA04BA6F8CE7190F4DC078EBA83160D1A7A792ABFA1F7E7C25BB3A4632B2BCB138E3596AE01F8905C7F7DE44E77221374AC174F289801377D67A7546E1B7225F830E1CFEE8BBC2DA0ABC991324E7EAB8BC2443544AE9976BEB4603FC118DE2C159385D982B14067CD87895F6C3FBCDFB68D37FE82F8148C1B5F23107B3AF4449A0B30E0E05702D32E696F8C87D3ED"
#   doAssert pk4096.coef.toString(16).toUpperAscii() ==
#     "8ADC61794D5C5C2EC71AAA7CEC91F0FA632801C26C3518F67275C7C84B1A0EA9F6CC47643BC01D3A1B84F2E13179729D9CB6D66C514A065AC6AFB1DBA224325E50322061A4523FBDBC30B7DB5B9A4D731250C831096D2013F1106A865614B456A6B7A4A3D11134C9B29416DDD24A89B586226E7A90972F7247AE0548056D61D73F72B21EDDBB15EB57A1D47449B970AE6EB622A35509BB0B21CE222CD898D31F62F7E7227F129220A7D43E513CA2DE2C6E9AEDCB5CF9994243B984941EF9459F5BECB4F58CB42FE4D843CC417BF4235D2817810B83F103EF49D218E3CE41C98A761690F0741665E467409901BBDC92F692C79AAA193894AD8587FD1052FE2D8A"

#   doAssert pk4096.sign_SHA256("test message\n").toHex().toUpperAscii() ==
#     "9CB2F9155D37572E358A452734E867626331637CBAC2F87BB49F4F11FDD1C88497D5988E0DB260A84CE2B982E45DE7DE1C25BD12E0CC15DA0C2207A0B9EDCE1C5925ED85DB3AAA6DBD2FB75791C406B5E51039929D099E6AB311CB88954C00CD745FB092F284E19613B6D7EB810A54EC7DA59E103BAB3EA243793350B403DC40A65F96FF8182314F23D63FC04EC5AF07F1D2A11298A4CF991BC492A3BF5FDCD099114F69DA858C1C78F2179763DD98555D71510BB5270556A9634AD536DD3C3A6A32BCC6A5C510C15F305FD0BEC818E6BF040AED9689A86F5DD57A61EC2AD6DAB437D7896CA71D19860F301CDBA073785F51A311181BE20BC48E0A187F339634278BB2D7EDC37F93C86AAAF83E0BF73634BD65BBAF517293AAB4F8E55A1958846EA14B92635201F7991219E8C61481B478FC40AC75C086DF5AA7A20FE70631BFDB335D07F76012F0C24F813976B65B00C3AF3497EAA6E55E212AEA3958BA993CBDA43B6F561543D6FD6D6C692BE286B8A62109FB5D078DD4F8FFF811D5AC26F387EB5B45AF06D474C35431F906C5F264150F6BA1711C70084F9574585C8D51178685CD723BB6F100E1649E2AD40F48210575BB040D2541EDC41C954962876E6224A144947907FCFCB76EA0B0D7AD45E7E0307EFFFCE5C5E065FA2584F73D893D57EFB7EC3C81C128E6C7EF289EAA900B7F3EFE86B93B33AEB79730FE02D5CB32"

# block:
#   let pkcs8 = decodePrivateKey(readFile("tests/data/pkcs8.txt"))
#   #doAssert pkcs8.size == 2048

# block:
#   let
#     privateKey = decodePrivateKey("""-----BEGIN PRIVATE KEY-----
#   MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
#   MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
#   NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
#   qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
#   p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
#   ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
#   VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
#   laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
#   sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
#   mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
#   dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
#   ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
#   DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
#   N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
#   0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
#   t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
#   AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
#   48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
#   DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
#   xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
#   mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
#   2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
#   et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
#   VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
#   TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
#   dn/RsYEONbwQSjIfMPkvxF+8HQ==
#   -----END PRIVATE KEY-----""")
#     message = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"

#   var signature = encode(privateKey.sign_SHA256(message), safe = true)
#   while signature[signature.high] == '=':
#     signature.setLen(signature.len - 1)

#   doAssert signature == "NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"
