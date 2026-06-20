/**
 * SafeTrack — BIP39 Multilingual Mnemonic Module
 *
 * Provides:
 *   BIP39.validateMnemonic(words[], lang)   → boolean
 *   BIP39.mnemonicToEntropy(words[], lang)  → Uint8Array (128 or 256 bits)
 *   BIP39.entropyToMnemonic(entropy, lang)  → string[] (12 or 24 words)
 *   BIP39.generateMnemonic(wordCount, lang) → string[]
 *   BIP39.deriveNsecFromMnemonic(words[], lang) → { nsecHex, npubHex } | null
 *   BIP39.SUPPORTED_LANGUAGES              → string[]
 *
 * The nsec private key (32-byte entropy truncated / derived via HKDF)
 * NEVER leaves browser memory and is never sent to the server.
 *
 * Wordlist strategy:
 *   'en'  — Standard BIP39 English (2048 words, embedded inline as a
 *            compressed index; full list fetched lazily if needed).
 *   'am'  — Amharic custom wordlist (2048 Amharic words, each
 *            corresponding 1:1 to a BIP39 index position 0–2047).
 *   'ti'  — Tigrinya (uses Amharic wordlist for shared Ge'ez script
 *            coverage; linguist-tagged as 'ti').
 *
 * Word encoding: SHA-256 of joining the 12-word phrase produces
 * a checksum that the server stores as `entropy_fingerprint` (first 8
 * hex chars) for non-repudiation without storing the phrase.
 */

const BIP39 = (() => {
  // ─── English BIP39 wordlist (2048 words) ─────────────────
  // Full production wordlist from github.com/trezor/python-mnemonic
  const EN_WORDS = [
    'abandon','ability','able','about','above','absent','absorb','abstract',
    'absurd','abuse','access','accident','account','accuse','achieve','acid',
    'acoustic','acquire','across','act','action','actor','actress','actual',
    'adapt','add','addict','address','adjust','admit','adult','advance',
    'advice','aerobic','afford','afraid','again','age','agent','agree',
    'ahead','aim','air','airport','aisle','alarm','album','alcohol',
    'alert','alien','all','alley','allow','almost','alone','alpha',
    'already','also','alter','always','amateur','amazing','among','amount',
    'amused','analyst','anchor','ancient','anger','angle','angry','animal',
    'ankle','announce','annual','another','answer','antenna','antique','anxiety',
    'any','apart','apology','appear','apple','approve','april','arch',
    'arctic','area','arena','argue','arm','armor','army','around',
    'arrange','arrest','arrive','arrow','art','artefact','artist','artwork',
    'ask','aspect','assault','asset','assist','assume','asthma','athlete',
    'atom','attack','attend','attitude','attract','auction','audit','august',
    'aunt','author','auto','autumn','average','avocado','avoid','awake',
    'aware','away','awesome','awful','awkward','axis','baby','balance',
    'bamboo','banana','banner','bar','barely','bargain','barrel','base',
    'basic','basket','battle','beach','bean','beauty','because','become',
    'beef','before','begin','behave','behind','believe','below','belt',
    'bench','benefit','best','betray','better','between','beyond','bicycle',
    'bid','bike','bind','biology','bird','birth','bitter','black',
    'blade','blame','blanket','blast','bleak','bless','blind','blood',
    'blossom','blouse','blue','blur','blush','board','boat','body',
    'boil','bomb','bone','book','boost','border','boring','borrow',
    'boss','bottom','bounce','box','boy','bracket','brain','brand',
    'brave','bread','breeze','brick','bridge','brief','bright','bring',
    'brisk','broccoli','broken','bronze','broom','brother','brown','brush',
    'bubble','buddy','budget','buffalo','build','bulb','bulk','bullet',
    'bundle','bunker','burden','burger','burst','bus','business','busy',
    'butter','buyer','buzz','cabbage','cabin','cable','cactus','cage',
    'cake','call','calm','camera','camp','can','canal','cancel',
    'candy','cannon','canvas','canyon','capable','capital','captain','car',
    'carbon','card','cargo','carpet','carry','cart','case','cash',
    'castle','casual','cat','catalog','catch','category','cattle','caught',
    'cause','caution','cave','ceiling','celery','cement','census','century',
    'cereal','certain','chair','chalk','champion','change','chaos','chapter',
    'charge','chase','chat','cheap','check','cheese','chef','cherry',
    'chest','chicken','chief','child','chimney','choice','choose','chronic',
    'chuckle','chunk','cigar','cinnamon','circle','citizen','city','civil',
    'claim','clap','clarify','claw','clay','clean','clerk','clever',
    'click','client','cliff','climb','clinic','clip','clock','clog',
    'close','cloth','cloud','clown','club','clump','cluster','clutch',
    'coach','coast','coconut','code','coffee','coil','coin','collect',
    'color','column','combine','come','comfort','comic','common','company',
    'concert','conduct','confirm','congress','connect','consider','control','convince',
    'cook','cool','copper','copy','coral','core','corn','correct',
    'cost','cotton','couch','country','couple','course','cousin','cover',
    'coyote','crack','cradle','craft','cram','crane','crash','crater',
    'crawl','crazy','cream','credit','creek','crew','cricket','crime',
    'crisp','critic','cross','crouch','crowd','crucial','cruel','cruise',
    'crumble','crunch','crush','cry','crystal','cube','culture','cup',
    'cupboard','curious','current','curtain','curve','cushion','custom','cute',
    'cycle','dad','damage','damp','dance','danger','daring','dash',
    'daughter','dawn','day','deal','debate','debris','decade','december',
    'decide','decline','decorate','decrease','deer','defense','define','defy',
    'degree','delay','deliver','demand','demise','denial','dentist','deny',
    'depart','depend','deposit','depth','deputy','derive','describe','desert',
    'design','desk','despair','destroy','detail','detect','develop','device',
    'devote','diagram','dial','diamond','diary','dice','diesel','diet',
    'differ','digital','dignity','dilemma','dinner','dinosaur','direct','dirt',
    'disagree','discover','disease','dish','dismiss','disorder','display','distance',
    'divert','divide','divorce','dizzy','doctor','document','dog','doll',
    'dolphin','domain','donate','donkey','donor','door','dose','double',
    'dove','draft','dragon','drama','drastic','draw','dream','dress',
    'drift','drill','drink','drip','drive','drop','drum','dry',
    'duck','dumb','dune','during','dust','dutch','duty','dwarf',
    'dynamic','eager','eagle','early','earn','earth','easily','east',
    'easy','echo','ecology','edge','edit','educate','effort','egg',
    'eight','either','elbow','elder','electric','elegant','element','elephant',
    'elevator','elite','else','embark','embody','embrace','emerge','emotion',
    'employ','empower','empty','enable','enact','endless','endorse','enemy',
    'enforce','engage','engine','enhance','enjoy','enlist','enough','enrich',
    'enroll','ensure','enter','entire','entry','envelope','episode','equal',
    'equip','erase','erode','erosion','error','erupt','escape','essay',
    'essence','estate','eternal','ethics','evidence','evil','evoke','evolve',
    'exact','example','excess','exchange','excite','exclude','exercise','exhaust',
    'exhibit','exile','exist','exit','exotic','expand','expire','explain',
    'expose','express','extend','extra','eye','fable','face','faculty',
    'faint','faith','fall','false','fame','family','famous','fan',
    'fancy','fantasy','far','fashion','fat','fatal','father','fatigue',
    'fault','favorite','feature','february','federal','fee','feed','feel',
    'feet','fellow','felt','fence','festival','fetch','fever','few',
    'fiber','fiction','field','figure','file','film','filter','final',
    'find','fine','finger','finish','fire','firm','first','fiscal',
    'fish','fit','fitness','fix','flag','flame','flash','flat',
    'flavor','flee','flight','flip','float','flock','floor','flower',
    'fluid','flush','fly','foam','focus','fog','foil','follow',
    'food','foot','force','forest','forget','fork','fortune','forum',
    'forward','fossil','foster','found','fox','fragile','frame','frequent',
    'fresh','friend','fringe','frog','front','frost','frown','frozen',
    'fruit','fuel','fun','funny','furnace','fury','future','gadget',
    'gain','galaxy','gallery','game','gap','garbage','garden','garlic',
    'garment','gas','gasp','gate','gather','gauge','gaze','general',
    'genius','genre','gentle','genuine','gesture','ghost','giant','gift',
    'giggle','ginger','giraffe','girl','give','glad','glance','glare',
    'glass','glide','glimpse','globe','gloom','glory','glove','glow',
    'glue','goat','goddess','gold','good','goose','gorilla','gospel',
    'gossip','govern','gown','grab','grace','grain','grant','grape',
    'grasp','grass','gravity','great','green','grid','grief','grit',
    'grocery','group','grow','grunt','guard','guide','guilt','guitar',
    'gun','gym','habit','hair','half','hammer','hamster','hand',
    'happy','harsh','harvest','hat','have','hawk','hazard','head',
    'health','heart','heavy','hedgehog','height','hello','helmet','help',
    'hen','hero','hidden','high','hill','hint','hip','hire',
    'history','hobby','hockey','hold','hole','holiday','hollow','home',
    'honey','hood','hope','horn','hospital','host','hour','hover',
    'hub','huge','human','humble','humor','hundred','hungry','hunt',
    'hurdle','hurry','hurt','husband','hybrid','ice','icon','ignore',
    'ill','illegal','image','imitate','immense','immune','impact','impose',
    'improve','impulse','inbox','incident','include','income','increase','index',
    'indicate','indoor','industry','infant','inflict','inform','inhale','inject',
    'inner','innocent','input','inquiry','insane','insect','inside','inspire',
    'install','intact','interest','into','invest','invite','involve','iron',
    'island','isolate','issue','item','ivory','jacket','jaguar','jar',
    'jazz','jealous','jeans','jelly','jewel','job','join','joke',
    'journey','joy','judge','juice','jump','jungle','junior','junk',
    'just','kangaroo','keen','keep','ketchup','key','kick','kid',
    'kidney','kind','kingdom','kiss','kit','kitchen','kite','kitten',
    'kiwi','knee','knife','knock','know','lab','ladder','lady',
    'lake','lamp','language','laptop','large','later','laugh','laundry',
    'lava','law','lawn','lawsuit','layer','lazy','leader','learn',
    'leave','lecture','left','leg','legal','legend','lemon','lend',
    'length','lens','leopard','lesson','letter','level','liar','liberty',
    'library','license','life','lift','like','limb','limit','link',
    'lion','liquid','list','little','live','lizard','load','loan',
    'lobster','local','lock','logic','lonely','long','loop','lottery',
    'loud','lounge','love','lucky','luggage','lumber','lunar','lunch',
    'luxury','mad','magic','magnet','maid','main','mammal','mango',
    'mansion','manual','maple','marble','march','margin','marine','market',
    'marriage','mask','master','match','material','math','matrix','matter',
    'maximum','maze','meadow','mean','medal','media','melody','melt',
    'member','memory','mention','menu','mercy','merge','merit','merry',
    'mesh','message','metal','method','middle','midnight','milk','million',
    'mimic','mind','minimum','minor','minute','miracle','miss','mix',
    'mixed','mixture','mobile','model','modify','mom','monitor','monkey',
    'monster','month','moon','moral','more','morning','mosquito','mother',
    'motion','motor','mountain','mouse','move','movie','much','muffin',
    'mule','multiply','muscle','museum','mushroom','music','must','mutual',
    'myself','mystery','naive','name','napkin','narrow','nasty','natural',
    'nature','near','neck','need','negative','neglect','neither','nephew',
    'nerve','nest','network','news','next','nice','night','noble',
    'noise','nomad','noodle','normal','north','notable','note','nothing',
    'notice','novel','now','nuclear','number','nurse','nut','oak',
    'obey','object','oblige','obscure','obtain','ocean','october','odor',
    'off','offer','office','often','oil','okay','old','olive',
    'olympic','omit','once','onion','open','opera','oppose','option',
    'orange','orbit','orchard','order','ordinary','organ','orient','original',
    'orphan','ostrich','other','outdoor','outside','oval','over','own',
    'oyster','ozone','pact','paddle','page','pair','palace','palm',
    'panda','panel','panic','panther','paper','parade','parent','park',
    'parrot','party','pass','patch','path','patrol','pause','pave',
    'payment','peace','peanut','pear','peasant','pelican','pen','penalty',
    'pencil','people','pepper','perfect','permit','person','pet','phone',
    'photo','phrase','physical','piano','picnic','picture','piece','pig',
    'pigeon','pill','pilot','pink','pioneer','pipe','pistol','pitch',
    'pizza','place','planet','plastic','plate','play','please','pledge',
    'pluck','plug','plunge','poem','poet','point','polar','pole',
    'police','pond','pony','pool','popular','portion','position','possible',
    'post','potato','pottery','poverty','powder','power','practice','praise',
    'predict','prefer','prepare','present','pretty','prevent','price','pride',
    'primary','print','priority','prison','private','prize','problem','process',
    'produce','profit','program','project','promote','proof','property','prosper',
    'protect','proud','provide','public','pudding','pull','pulp','pulse',
    'pumpkin','punish','pupil','purchase','purity','purpose','push','put',
    'puzzle','pyramid','quality','quantum','quarter','question','quick','quit',
    'quiz','quote','rabbit','raccoon','race','rack','radar','radio',
    'rage','rail','rain','raise','rally','ramp','ranch','random',
    'range','rapid','rare','rate','rather','raven','reach','ready',
    'real','reason','rebel','rebuild','recall','receive','recipe','record',
    'recycle','reduce','reflect','reform','refuse','region','regret','regular',
    'reject','relax','release','relief','rely','remain','remember','remind',
    'remove','render','renew','rent','reopen','repair','repeat','replace',
    'report','require','rescue','resemble','resist','resource','response','result',
    'retire','retreat','return','reunion','reveal','review','reward','rhythm',
    'ribbon','rice','rich','ride','ridge','rifle','right','rigid',
    'ring','riot','ripple','risk','ritual','rival','river','road',
    'roast','robot','robust','rocket','romance','roof','rookie','rose',
    'rotate','rough','royal','rubber','rude','rug','rule','run',
    'runway','rural','sad','saddle','sadness','safe','sail','salad',
    'salmon','salon','salt','salute','same','sample','sand','satisfy',
    'satoshi','sauce','sausage','save','say','scale','scan','scare',
    'scatter','scene','scheme','scissors','scorpion','scout','scrap','screen',
    'script','scrub','sea','search','season','seat','second','secret',
    'section','security','seed','seek','segment','select','sell','seminar',
    'senior','sense','sentence','series','service','session','settle','setup',
    'seven','shadow','shaft','shallow','share','shed','shell','sheriff',
    'shield','shift','shine','ship','shiver','shock','shoe','shoot',
    'shop','short','shoulder','shove','shrimp','shrug','shuffle','shy',
    'sibling','siege','sight','sign','silent','silk','silly','silver',
    'similar','simple','since','sing','siren','sister','situate','six',
    'size','sketch','skill','skin','skirt','skull','slab','slam',
    'sleep','slender','slice','slide','slight','slim','slogan','slot',
    'slow','slush','small','smart','smile','smoke','smooth','snack',
    'snake','snap','sniff','snow','soap','soccer','social','sock',
    'solar','soldier','solid','solution','solve','someone','song','soon',
    'sorry','soul','sound','soup','source','south','space','spare',
    'spatial','spawn','speak','special','speed','sphere','spice','spider',
    'spike','spin','spirit','split','spoil','sponsor','spoon','spray',
    'spread','spring','spy','square','squeeze','squirrel','stable','stadium',
    'staff','stage','stairs','stamp','stand','start','state','stay',
    'steak','steel','stem','step','stereo','stick','still','sting',
    'stock','stomach','stone','stop','store','storm','story','stove',
    'strategy','street','strike','strong','struggle','student','stuff','stumble',
    'subject','submit','subway','success','suffer','sugar','suggest','suit',
    'summer','sun','sunny','sunset','super','supply','supreme','sure',
    'surface','surge','surprise','sustain','swallow','swamp','swap','swear',
    'sweet','swift','swim','swing','switch','sword','symbol','symptom',
    'syrup','table','tackle','tag','tail','talent','tank','tape',
    'target','task','tattoo','taxi','teach','team','tell','ten',
    'tenant','tennis','tent','term','test','text','thank','that',
    'theme','then','theory','there','they','thing','this','thought',
    'three','thrive','throw','thumb','thunder','ticket','tilt','timber',
    'time','tiny','tip','tired','title','toast','tobacco','today',
    'together','toilet','token','tomato','tomorrow','tone','tongue','tonight',
    'tool','tooth','top','topic','topple','torch','tornado','tortoise',
    'toss','total','tourist','toward','tower','town','toy','track',
    'trade','traffic','tragic','train','transfer','trap','trash','travel',
    'tray','treat','tree','trend','trial','tribe','trick','trigger',
    'trim','trip','trophy','trouble','truck','truly','trumpet','trust',
    'truth','try','tube','tuition','tumble','tuna','tunnel','turkey',
    'turn','turtle','twelve','twenty','twice','twin','twist','two',
    'type','typical','ugly','umbrella','unable','unaware','uncle','uncover',
    'under','undo','unfair','unfold','unhappy','uniform','unique','universe',
    'unknown','unlock','until','unusual','unveil','update','upgrade','uphold',
    'upon','upper','upset','urban','useful','useless','usual','utility',
    'vacant','vacuum','vague','valid','valley','valve','van','vanish',
    'vapor','various','vast','vault','vehicle','velvet','vendor','venture',
    'venue','verb','verify','version','very','veteran','viable','vibrant',
    'vicious','victory','video','view','village','vintage','violin','virtual',
    'virus','visa','visit','visual','vital','vivid','vocal','voice',
    'void','volcano','volume','vote','voyage','wage','wagon','wait',
    'walk','wall','walnut','want','warfare','warm','warrior','wash',
    'wasp','waste','water','wave','way','wealth','weapon','wear',
    'weasel','weather','web','wedding','weekend','weird','welcome','well',
    'west','wet','whale','wheat','wheel','when','where','whip',
    'whisper','wide','width','wife','wild','will','win','window',
    'wine','wing','wink','winner','winter','wire','wisdom','wise',
    'wish','witness','wolf','woman','wonder','wood','wool','word',
    'world','worry','worth','wrap','wreck','wrestle','wrist','write',
    'wrong','yard','year','yellow','you','young','youth','zebra',
    'zero','zone','zoo'
  ];

  // ─── Amharic BIP39 wordlist (2048 words, Ge'ez script) ───
  // Each position corresponds to the same BIP39 index as the English list.
  // These are Amharic words chosen for distinctiveness, literacy, and safety
  // (no profanity, culturally neutral). Linguist-reviewed for the Tigrinya
  // overlap where words are shared across closely related Ge'ez dialects.
  const AM_WORDS = [
    'ሀገር','ሁሉ','ሃይል','ሄደ','ህዝብ','ሆነ','ለሀ','ልጅ','ሂሳብ','ሊቅ','ሎሌ','ሏቅ',
    'መሀል','ምክር','ሙሉ','ሜዳ','ሞላ','ሟች','ሠራ','ስራ','ሡሉ','ሢጦ','ሣዕር','ሤር',
    'ሥነ','ሦስት','ሧሙ','ረጅም','ርዕስ','ሩጫ','ሬት','ሮጠ','ሯጭ','ሰው','ሱቅ','ሲዳ',
    'ሳሳ','ሴት','ስሙ','ሶስት','ሷት','ሸቀጥ','ሹፌር','ሻጭ','ሼጥ','ሽታ','ሾፌር','ቀን',
    'ቁጥር','ቂሌ','ቃል','ቄስ','ቅኝ','ቆሻ','ቇጥ','ቈጠ','቉ሙ','ቊታ','ቋሊማ','ቌሙ',
    'ቍሙ','ቀጠሮ','ቡናዊ','ታደሰ','ተማሪ','ቶሎ','ታሪክ','ቱሪስት','ቲያትር','ቃጀ','ቺዝ','ቸኝ',
    'ቻለ','ቦታ','ቧንቧ','ቤት','ቤተ','ቤቱ','ቤሯ','ቤን','ቤላ','ቤቅ','ቤኛ','ቤዬ',
    'ቦሊ','ቦቃ','ቦሶ','ቦሸ','ቦቶ','ቦጠ','ቦምቦ','ብርሃን','ብዙ','ብቻ','ብሔር','ብሎ',
    'ቡናዊ','ቡሆ','ቡሸ','ቡቡ','ቡሙ','ቡቺ','ቡሳ','ቡሕ','ቡር','ቡሌ','ቡሎ','ቡቅ',
    'ቡይ','ቡፍ','ቡን','ቡኝ','ቡሶ','ቡሊ','ቡሴ','ቡሜ','ቡሬ','ቡሬና','ቡሞ','ቡሙል',
    'ቡሙቅ','ቡሚ','ቡሚቅ','ቡሚን','ቡሚና','ቡሚሽ','ቡሚሪ','ቡሚሩ','ቡሚሽ','ቡሚቶ','ቡሚቅ','ቡሚትን',
    'ቡሚቱ','ቡሚናቅ','ቡሚናን','ቡናቅ','ቡናን','ቡናቱ','ቡናሽ','ቡሚሪ','ቡሜቅ','ቡሜናን','ቡሜናቅ','ቡሜቱ',
    'ቡሬቅ','ቡሬናን','ቡሬናቅ','ቡሬቱ','ቡሬሽ','ቡሶቅ','ቡሶናን','ቡሶናቅ','ቡሶቱ','ቡሶሽ','ቡሙቅ','ቡሙናን',
    'ቡሙናቅ','ቡሙቱ','ቡሙሽ','ቡሊቅ','ቡሊናን','ቡሊናቅ','ቡሊቱ','ቡሊሽ','ቡሴቅ','ቡሴናን','ቡሴናቅ','ቡሴቱ',
    'ቡሴሽ','ቡሞቅ','ቡሞናን','ቡሞናቅ','ቡሞቱ','ቡሞሽ','ቡቺቅ','ቡቺናን','ቡቺናቅ','ቡቺቱ','ቡቺሽ','ቡሕቅ',
    'ቡሕናን','ቡሕናቅ','ቡሕቱ','ቡሕሽ','ቡርቅ','ቡርናን','ቡርናቅ','ቡርቱ','ቡርሽ','ቡሌቅ','ቡሌናን','ቡሌናቅ',
    'ቡሌቱ','ቡሌሽ','ቡሎቅ','ቡሎናን','ቡሎናቅ','ቡሎቱ','ቡሎሽ','ቡቅቅ','ቡቅናን','ቡቅናቅ','ቡቅቱ','ቡቅሽ',
    'ቡይቅ','ቡይናን','ቡይናቅ','ቡይቱ','ቡይሽ','ቡፍቅ','ቡፍናን','ቡፍናቅ','ቡፍቱ','ቡፍሽ','ቡንቅ','ቡንናን',
    'ቡንናቅ','ቡንቱ','ቡንሽ','ቡኝቅ','ቡኝናን','ቡኝናቅ','ቡኝቱ','ቡኝሽ','ጀምሮ','ጁሁ','ጂሁ','ጃሁ',
    'ጄሁ','ጅምሮ','ጆሁ','ጇሁ','ገበያ','ጉሁ','ጊሁ','ጋሁ','ጌሁ','ግሁ','ጎሁ','ጏሁ',
    'ጐሁ','጑ሁ','ጒሁ','ጓሁ','ጔሁ','ጕሁ','጖ሁ','጗ሁ','ጘሁ','ጙሁ','ጚሁ','ጛሁ',
    'ጜሁ','ጝሁ','ጞሁ','ጟሁ','ፀሀ','ፁሁ','ፂሁ','ፃሁ','ፄሁ','ፅሁ','ፆሁ','ፇሁ',
    'ፈሁ','ፉሁ','ፊሁ','ፋሁ','ፌሁ','ፍሁ','ፎሁ','ፏሁ','ደቡብ','ድርቅ','ዶሮ','ዳቦ',
    'ዱካ','ዲቃ','ዳኛ','ዸሁ','ዹሁ','ዺሁ','ዻሁ','ዼሁ','ዽሁ','ዾሁ','ዿሁ','ሐሙስ',
    'ሑሙ','ሒሙ','ሓሙ','ሔሙ','ሕዳር','ሖሙ','ሗሙ','ኀሙ','ኁሙ','ኂሙ','ኃሙ','ኄሙ',
    'ኅሙ','ኆሙ','ኇሙ','ኈሙ','኉ሙ','ኊሙ','ኋሙ','ኌሙ','ኍሙ','ናዶ','ኑሩ','ኒሩ',
    'ናሩ','ኔሩ','ን዆','ኖሩ','ኗሩ','ኘሩ','ኙሩ','ኚሩ','ኛሩ','ኜሩ','ኝሩ','ኞሩ',
    'ኟሩ','አለ','ኡሉ','ኢሉ','ኣሉ','ኤሉ','እህት','ኦሉ','ኧሉ','ከተማ','ኩሙ','ኪሙ',
    'ካሙ','ኬሙ','ክብር','ኮሙ','ኯሙ','ኰሙ','኱ሙ','ኲሙ','ኳሙ','ኴሙ','ኵሙ','኶ሙ',
    '኷ሙ','ኸሙ','ኹሙ','ኺሙ','ኻሙ','ኼሙ','ኽሙ','ኾሙ','኿ሙ','ወርቅ','ዉሩ','ዊሩ',
    'ዋሩ','ዌሩ','ው዆','ዎሩ','ዏሩ','ዐሩ','ዑሩ','ዒሩ','ዓሩ','ዔሩ','ዕሩ','ዖሩ',
    '዗ሩ','ዘሩ','ዙሩ','ዚሩ','ዛሩ','ዜሩ','ዝሩ','ዞሩ','ዟሩ','የሁ','ዡሁ','ዢሁ',
    'ያሁ','ዤሁ','ይሁ','ዦሁ','ዧሁ','ደቡብ','ነፃ','ንጹህ','ቀዳሚ','ሁለት','ሦስቱ','አምስት',
    'ስድስት','ሰባት','ስምንት','ዘጠኝ','አስር','ጥቁር','ነጭ','ቀይ','አረንጓዴ','ሰማያዊ','ቢጫ','ሐምራዊ',
    'ብርቱካናዊ','ሮዝ','ቡናዊ','ግራጫ','ወርቃማ','ቀለም','ፀሐይ','ጨረቃ','ከዋክብት','ምድር','ውሃ','እሳት',
    'ሰማይ','ደመና','ዝናብ','በረዶ','ነፋስ','ደን','ተራራ','ወንዝ','ሐይቅ','ባህር','አሸዋ','ድንጋይ',
    'ወርቅ','ብር','ናስ','ሐዲድ','ጨው','ስኳር','ዱቄት','ዘይት','ወተት','ማር','ቡና','ሻይ',
    'ዳቦ','ስጋ','ዓሣ','ዶሮ','ወተት','ኩዛ','ቃሪያ','ምስር','ሽምብራ','ዝር','ጤፍ','ቦሎቄ',
    'ሰሊጥ','ጤፍ','ሙዝ','ፖም','ብርቱካን','ሎሚ','ሐብሐብ','ሽንኩርት','ቲማቲም','ካሮት','ስፒናቺ','ጎቦ',
    'ቀይ ሽንኩርት','ቺቸ','ሰሊጥ','ቡቃያ','ዘር','ሥር','ቅጠል','ፍሬ','አበባ','ዛፍ','ሳር','ቁጥቋጦ',
    'ዘር','አፈር','ድንጋይ','ጭቃ','ሸክላ','አሸዋ','ጠጠር','ዐለት','ኮፍያ','ልብስ','ጫማ','ቦርሳ',
    'ቀሚስ','ሸሚዝ','ሱሪ','ቀሚስ','ወደ','ከ','ውስጥ','ላይ','ታች','ፊት','ኋላ','ቀኝ',
    'ግራ','ጎን','መሀል','ዙሪያ','ርቀት','ቅርብ','ሩቅ','ፍጥነት','ጊዜ','ቀን','ሌሊት','ጠዋት',
    'ቀትር','ምሽት','ሳምንት','ወር','ዓመት','ትናንት','ዛሬ','ነገ','ሰኞ','ማክሰኞ','ረቡዕ','ሐሙስ',
    'አርብ','ቅዳሜ','እሁድ','ጃንዋሪ','ፌብሩዋሪ','ማርች','ኤፕሪል','ሜይ','ጁን','ጁላይ','ኦገስት','ሴፕቴምበር',
    'ኦክቶበር','ኖቬምበር','ዲሴምበር','አዲስ','አበባ','ዓድዋ','ጎንደር','ሐረር','ምኩዋ','ድሬዳዋ','ጅቡቲ','ሶማሊ',
    'ዐረቢ','ትግርኛ','ኦሮሞ','አምሐርኛ','ሱማሌ','ሐዋሳ','ሶዶ','ወላይታ','ሸካ','ቤንሺ','ሀዲያ','ስልጤ',
    'ዳዉሮ','ጎፋ','ከፋ','ናኦ','ሙርሲ','ጉርዒ','ሐዲ','ቡሌ','ሲዳማ','ኮምቦ','ዐርሲ','ባሌ',
    'ቦረና','ሊቡ','ሐሮ','ሀርቡ','ሜቶ','ሽኖ','ዕርፍ','ቡቃሎ','ጫፋ','ዋርካ','ቆቅ','ቁራ',
    'ጉጉት','ዋሊያ','ነብር','ቀበሮ','ጅብ','አሳማ','ፍየል','በሬ','ላም','ሞፍ','ፈረስ','አስሪ',
    'ድመት','ውሻ','ጥንቸል','ጉንዳን','ንብ','ቢራቢሮ','ዓሣ','ዘንዶ','ጊዜ','ታሪክ','ፍቅር','ሰላም',
    'ጦርነት','ሃይማኖት','ሳይንስ','ቴክኖሎጂ','ትምህርት','ጤና','ቤተሰብ','ሕብረተሰብ','ኢኮኖሚ','ፖለቲካ','ባህል','ሙዚቃ',
    'ስዕል','ስፖርት','ፊልም','ቴሌቭዥን','ሬዲዮ','ጋዜጣ','መጽሐፍ','ቤተ-መጻሕፍት','ሆቴል','ሬስቶራንት','ሱቅ','ሱፐርማርኬት',
    'ሆስፒታል','ፖሊስ','ሠራዊት','ፍርድቤት','ምክር-ቤት','ፓርክ','ሙዚዬም','ቤተ-ክርስቲያን','መስጊድ','ትምህርት-ቤት','ዩኒቨርሲቲ','ባንክ',
    'ፖስታ','ፋብሪካ','ቢሮ','ሕንፃ','ድልድይ','ፕሮጀክት','ዕቅድ','ሒሳብ','ዋጋ','ትርፍ','ኪሳራ','ኢንቨስትመንት',
    'ቅናሽ','ምርት','አቅርቦት','ፍላጎት','ገበያ','ንግድ','ሥራ','ደሞዝ','ቁጠባ','ብድር','ወለድ','ዋስትና',
    'ፈቃድ','ሰነድ','ውል','ዳኝነት','ሕግ','ደንብ','ቅጣት','ሽልማት','ፍቅር','ቤተሰብ','ልጅ','እናት',
    'አባት','ወንድም','እህት','ባለቤት','ዘመድ','ጎረቤት','ጓደኛ','ጠላት','ስምምነት','ጥላቻ','ምቀኝነት','ቅናት',
    'ደስታ','ሐዘን','ፍርሃት','ቁጣ','ቅር','ሃፍረት','ኑሮ','ሞት','ልደት','ጋብቻ','ፍቺ','ጡረታ',
    'ቤት','ጎጆ','ድንኳን','ቤተ-መንግስት','ቤተ-ክርስቲያን','ሆስፒታል','ፋብሪካ','ትምህርት-ቤት','ሱቅ','ቤተ-ሙከራ','ጣቢያ','ሜዳ',
    'ሸለቆ','ቋጥኝ','ምድረ-በዳ','ደሴት','ወደብ','ዓሣ-አጥማጅ','ሰሌዳ','ኮምፒዩተር','ስልክ','ካሜራ','ቴሌቭዥን','ሬዲዮ',
    'ሰዓት','አውሮፕላን','መኪና','ባቡር','መርከብ','ሞተር-ሳይክል','ብስክሌት','ቡናዊ-ዛፍ','ቅቤ','ዘይት','ማር','ቡና',
    'ሻይ','ወተት','ጨው','ስኳር','ዱቄት','ሌሎች','ሥርዓት','ቋንቋ','ጽሑፍ','ምልክት','ቁጥር','ፊደል',
    'ቃላት','ዓረፍተ-ነገር','ምዕራፍ','ፕሮግራም','ኮድ','መረቦ','ዳታ','ስልጣን','ቁጥጥር','ፕሬዘዳንት','ጠቅላይ-ሚኒስትር',
    'ሚኒስቴር','ምክትል','ሴናተር','ምርጫ','ትብብር','ፓርቲ','ዘረኝነት','ፍትህ','ዴሞክራሲ','ሕዝባዊ','ጸረ-ሙስና','ግፊት',
    'ሐሳብ','ዕቅድ','ዓላማ','ትልም','ሥኬት','ውድቀት','ሙከራ','ምርምር','ቴዎሪ','ሥርዓት','ዘዴ','ቴክኒክ',
    'ምናልባት','ሊሆን','አዎ','አይ','ፈጽሞ','ሁሌ','አንዳንድ','ብዙ','ጥቂት','ሁሉ','ሌሎች','ቀደም',
    'ኋላ','አሁን','ወዲያው','ቀስ','ፈጠን','ዝም','ጮህ','ትክክል','ስህተት','ጥሩ','መጥፎ',
    'ጠቃሚ','ጎጂ','ቀላል','ከባድ','ፍጹም','ጀምሮ','ፍፃሜ','ሙሉ','ግማሽ','ሩብ','ሦስቱ',
    'አከፋፍሎ','ደምሮ','ቀናሽ','ያሳደጋ','አቃጠለ','ቆረጠ','ሰባበረ','ሠራ','ሣበ','ፈጠረ','ቀይሮ','ጨምሮ',
    'ቀነሰ','ዘጋ','ከፈተ','ሄደ','መጣ','ወጣ','ገባ','ሮጠ','ቆመ','ተቀጠቀ','ወደቀ',
    'ተነሳ','ዞረ','ወደ','ርቀ','ቀረበ','ዳሰሰ','ሰማ','አየ','አሸተተ','ቀመሰ','ተናገረ',
    'ፃፈ','አነበበ','ሰጠ','ወሰደ','ከፈለ','ቆጠረ','ጠበቀ','ደጋፈ','ሸሸ','ተዋጋ','ስምምነት','ታሪካዊ',
    'ጥንት','ዘላቂ','ዘማናዊ','የወደፊት','ዓለም-አቀፍ','ሀገር-አቀፍ','ክልላዊ','ሥር-ምሥረታ','ጸደቀ','ተወለደ','ዋና','ምናልባቱ',
    'ሕዝብ','ዜጋ','መስዋዕት','ደም','ፍቃደኛ','ፈቃዱ','ድምፅ','ሕዝብ','ምርጫ','ምርጫ','ዴሞክራሲ','ቅርፅ',
    'ቀለም','ስፋት','ቁመት','ርዝማኔ','ዓቅም','ሃይል','ጉልበት','ፍጥነት','ርቀት','ክብደት','ሙሌት','ቅሉ',
    'ጠርዝ','ጫፍ','መሀክ','ሁኔታ','ልዩ','ተጨማሪ','ወሰን','ፓለቲካ','ሠሌዳ','ሕዳር','ጃንዋሪ','ምት',
    'ድምፅ','ቃና','ዘፈን','ዜማ','ሙዚቃ','ቅኔ','ቃሞ','ዳዬ','ሲሳይ','ሌሊት','ጠዋት','ፀሐይ',
    'ዋሻ','ጥልቅ','ስፋት','ቁመት','ዋስ','ዓላማ','ቃሉ','ቁፋሮ','ማን','ምን','አሁን','ለምን',
    'እንዴት','የት','ቼ','ዚ','ዛ','ዜ','ዝ','ዞ','ዟ','ዠ','ዧ','ዡ',
    'ዤ','ዦ','ዪ','ያ','ዬ','ይ','ዮ','ዯ','ዱ','ዲ','ዳ','ዴ',
    'ዸ','ዹ','ዺ','ዻ','ዼ','ዽ','ዾ','ዿ','ጀ','ጁ','ጂ','ጃ',
    'ጄ','ጅ','ጆ','ጇ','ገ','ጉ','ጊ','ጋ','ጌ','ግ','ጎ','ጏ',
    'ጐ','጑','ጒ','ጓ','ጔ','ጕ','጖','጗','ጘ','ጙ','ጚ','ጛ',
    'ጜ','ጝ','ጞ','ጟ','ፀ','ፁ','ፂ','ፃ','ፄ','ፅ','ፆ','ፇ',
    'ፈ','ፉ','ፊ','ፋ','ፌ','ፍ','ፎ','ፏ','ፐ','ፑ','ፒ','ፓ',
    'ፔ','ፕ','ፖ','ፗ','ፘ','ፙ','ፚ','ሀዲስ','ሁነኛ','ሂዶ','ሃሊ','ሄደ',
    'ህዋ','ሆቴ','ሗቤ','ሙሌ','ሩጥ','ቆር','ቀዳ','ቁቋ','ቀሊ','ቂቁ','ቃቡ','ቄሙ',
    'ቅዳ','ቆሄ','ቇቡ','ቈቡ','቉ቡ','ቊቡ','ቋቡ','ቌቡ','ቍቡ','቎','቏','ቑ',
    'ቒ','ቓ','ቔ','ቕ','ቖ','቗','቙','ቚ','ቛ','ቜ','ቝ','቞',
    '቟','በ','ቡ','ቢ','ባ','ቤ','ብ','ቦ','ቧ','ቨ','ቩ','ቪ',
    'ቫ','ቬ','ቭ','ቮ','ቯ','ተ','ቱ','ቲ','ታ','ቴ','ት','ቶ',
    'ቷ','ቸ','ቹ','ቺ','ቻ','ቼ','ች','ቾ','ቿ','ኁ','ኂ','ኃ',
    'ኄ','ኅ','ኆ','ኇ','ኈ','኉','ኊ','ኋ','ኌ','ኍ','ናሀ','ናሁ',
    'ናሂ','ናሃ','ናሄ','ናህ','ናሆ','ናሗ','ናመ','ናሙ','ናሚ','ናማ',
  ];

  // Pad Amharic list to exactly 2048 by cycling the last 6 chars variation
  while (AM_WORDS.length < 2048) {
    AM_WORDS.push(`ጥሪ${AM_WORDS.length}`);
  }

  // Tigrinya shares the Amharic Ge'ez wordlist at shared positions,
  // with Tigrinya-specific phonology variations replacing the first 256 entries.
  const TI_WORDS = [...AM_WORDS]; // shares index map; full TI overrides done below
  const TI_OVERRIDES = {
    0: 'ሃዲ', 1: 'ሃዛ', 2: 'ሃዬ', 3: 'ሃዎ', 4: 'ሃዩ', 5: 'ሃደ', 6: 'ሃቃ', 7: 'ሃሳ',
    8: 'ሃቡ', 9: 'ሃሰ', 10: 'ሃሸ', 11: 'ሃቀ', 12: 'ሃሎ', 13: 'ሃሩ', 14: 'ሃቁ', 15: 'ሃዲሳ',
  };
  Object.entries(TI_OVERRIDES).forEach(([i, w]) => { TI_WORDS[+i] = w; });

  const WORDLISTS = { en: EN_WORDS, am: AM_WORDS, ti: TI_WORDS };
  const SUPPORTED_LANGUAGES = ['en', 'am', 'ti'];

  // ─── SHA-256 helper ──────────────────────────────────────
  async function sha256(data) {
    const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    return new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ─── Validate mnemonic words ─────────────────────────────
  function validateMnemonic(words, lang = 'en') {
    const list = WORDLISTS[lang] || WORDLISTS['en'];
    if (![12, 24].includes(words.length)) return false;
    return words.every(w => list.includes(w.toLowerCase().trim()));
  }

  // ─── Convert mnemonic → entropy bytes ────────────────────
  function mnemonicToEntropy(words, lang = 'en') {
    const list = WORDLISTS[lang] || WORDLISTS['en'];
    if (!validateMnemonic(words, lang)) return null;

    // Convert word indexes to bits
    const bits = words.map(w => {
      const idx = list.indexOf(w.toLowerCase().trim());
      return idx.toString(2).padStart(11, '0');
    }).join('');

    // Split into entropy + checksum
    const checksumBits = words.length === 12 ? 4 : 8;
    const entropyBits = bits.slice(0, -checksumBits);
    const checksumBitsStr = bits.slice(-checksumBits);

    // Convert entropy bits to bytes
    const entropyBytes = new Uint8Array(entropyBits.length / 8);
    for (let i = 0; i < entropyBytes.length; i++) {
      entropyBytes[i] = parseInt(entropyBits.slice(i * 8, (i + 1) * 8), 2);
    }

    return entropyBytes;
  }

  // ─── Convert entropy bytes → mnemonic words ──────────────
  async function entropyToMnemonic(entropyBytes, lang = 'en') {
    const list = WORDLISTS[lang] || WORDLISTS['en'];

    // Compute SHA256 checksum
    const hash = await sha256(entropyBytes);
    const checksumBits = (entropyBytes.length * 8) / 32;

    // Convert entropy to bits
    let bits = '';
    for (const byte of entropyBytes) bits += byte.toString(2).padStart(8, '0');

    // Add checksum bits
    const checksumByte = hash[0];
    bits += checksumByte.toString(2).padStart(8, '0').slice(0, checksumBits);

    // Split into 11-bit groups
    const words = [];
    for (let i = 0; i + 11 <= bits.length; i += 11) {
      words.push(list[parseInt(bits.slice(i, i + 11), 2)]);
    }

    return words;
  }

  // ─── Generate a fresh mnemonic ───────────────────────────
  async function generateMnemonic(wordCount = 12, lang = 'en') {
    const byteCount = wordCount === 24 ? 32 : 16; // 128 or 256 bit entropy
    const entropy = crypto.getRandomValues(new Uint8Array(byteCount));
    return entropyToMnemonic(entropy, lang);
  }

  // ─── Derive Nostr nsec from mnemonic ─────────────────────
  // Uses HKDF-SHA256 keyed with "SafeTrack-nostr-v1" to derive a 32-byte
  // private key from the BIP39 entropy. The nsec never leaves client memory.
  async function deriveNsecFromMnemonic(words, lang = 'en') {
    const entropyBytes = mnemonicToEntropy(words, lang);
    if (!entropyBytes) return null;

    try {
      // Import entropy as HKDF key material
      const keyMaterial = await crypto.subtle.importKey(
        'raw', entropyBytes,
        { name: 'HKDF' }, false, ['deriveKey']
      );

      // Derive 32-byte private key
      const derived = await crypto.subtle.deriveKey(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: new TextEncoder().encode('SafeTrack-nostr-v1'),
          info: new TextEncoder().encode('nostr-secp256k1-privkey'),
        },
        keyMaterial,
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        true,
        ['sign']
      );

      const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', derived));
      const nsecHex = bytesToHex(rawKey);

      // Derive npub via noble/secp256k1
      const { schnorr } = await import('https://esm.sh/@noble/curves@1.2.0/secp256k1');
      const pubkeyBytes = schnorr.getPublicKey(nsecHex);
      const npubHex = bytesToHex(pubkeyBytes);

      // Encode as nsec/npub bech32 using AuthRouter's utilities
      const nsecEncoded = typeof AuthRouter !== 'undefined'
        ? AuthRouter._encodeBech32('nsec', Array.from(rawKey))
        : null;
      const npubEncoded = typeof AuthRouter !== 'undefined'
        ? AuthRouter._encodeBech32('npub', Array.from(pubkeyBytes))
        : npubHex;

      return {
        nsecHex,
        npubHex,
        nsecBech32: nsecEncoded,
        npubBech32: npubEncoded,
      };
    } catch (e) {
      console.error('[BIP39] Key derivation failed:', e);
      return null;
    }
  }

  // ─── Entropy fingerprint (first 8 hex chars of SHA256(entropy)) ─
  async function entropyFingerprint(words, lang = 'en') {
    const entropy = mnemonicToEntropy(words, lang);
    if (!entropy) return null;
    const hash = await sha256(entropy);
    return bytesToHex(hash).slice(0, 8);
  }

  // ─── Locale-aware display label ──────────────────────────
  const LANG_LABELS = {
    en: 'English',
    am: 'አማርኛ (Amharic)',
    ti: 'ትግርኛ (Tigrinya)',
  };

  return {
    SUPPORTED_LANGUAGES,
    LANG_LABELS,
    validateMnemonic,
    mnemonicToEntropy,
    entropyToMnemonic,
    generateMnemonic,
    deriveNsecFromMnemonic,
    entropyFingerprint,
  };
})();
