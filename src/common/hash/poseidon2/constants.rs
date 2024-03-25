pub const WIDTH: usize = 8;
pub const DEGREE: usize = 7;
pub const ROUNDS_F: usize = 8;
pub const ROUNDS_P: usize = 22;
pub const ROUNDS: usize = ROUNDS_F + ROUNDS_P;

pub const MAT_INTERNAL_DIAG_M_1: [u64; WIDTH] = [
    0xa98811a1fed4e3a5,
    0x1cc48b54f377e2a0,
    0xe40cd4f6c5609a26,
    0x11de79ebca97a4a3,
    0x9177c73d8b7e929c,
    0x2a6fe8085797e791,
    0x3de6e93329f8d5ad,
    0x3f7af9125da962fe,
];

pub const ROUND_CONSTANTS: [[u64; WIDTH]; ROUNDS] = [
    [
        15949291268843349465,
        14644164809401934923,
        18420360874837380316,
        4756469047455716334,
        8685499049481102115,
        3799221349720045367,
        13676397835037157930,
        6566439050423619635,
    ],
    [
        17428268347612331188,
        2833135872454503769,
        4767009016213040191,
        2797635963551733652,
        5312339450141126694,
        5356668452102813289,
        1234059326449530173,
        7724302552453704877,
    ],
    [
        14868588146468890290,
        12825281145595371185,
        13097885453579304196,
        7905326782341128063,
        14167525334039893569,
        2082169701994688927,
        12190787523818595537,
        12602917751946636,
    ],
    [
        14890907856876319003,
        16552240149997473409,
        5634093690795187558,
        4883714163685656967,
        12440776365164557866,
        3923800234666204307,
        9858064884105950259,
        16040043470428402038,
    ],
    [5226594323142090582, 0, 0, 0, 0, 0, 0, 0],
    [1243120476974621208, 0, 0, 0, 0, 0, 0, 0],
    [12100812801659301173, 0, 0, 0, 0, 0, 0, 0],
    [11228203327983058121, 0, 0, 0, 0, 0, 0, 0],
    [13891617888374767564, 0, 0, 0, 0, 0, 0, 0],
    [5742893160230537107, 0, 0, 0, 0, 0, 0, 0],
    [3763472116988983643, 0, 0, 0, 0, 0, 0, 0],
    [2466655769425769160, 0, 0, 0, 0, 0, 0, 0],
    [6254574254498162968, 0, 0, 0, 0, 0, 0, 0],
    [14183251225809189357, 0, 0, 0, 0, 0, 0, 0],
    [11565357354521717084, 0, 0, 0, 0, 0, 0, 0],
    [17300657704266685688, 0, 0, 0, 0, 0, 0, 0],
    [310485250821938281, 0, 0, 0, 0, 0, 0, 0],
    [16853586468012618118, 0, 0, 0, 0, 0, 0, 0],
    [1978800426240373849, 0, 0, 0, 0, 0, 0, 0],
    [6948188224235462572, 0, 0, 0, 0, 0, 0, 0],
    [1486402152218690509, 0, 0, 0, 0, 0, 0, 0],
    [5669161690283398991, 0, 0, 0, 0, 0, 0, 0],
    [17943970877073781734, 0, 0, 0, 0, 0, 0, 0],
    [17926851897715769433, 0, 0, 0, 0, 0, 0, 0],
    [13052837496695000666, 0, 0, 0, 0, 0, 0, 0],
    [18138113741095562305, 0, 0, 0, 0, 0, 0, 0],
    [
        94277733998400326,
        10891359798487446420,
        18280773820738154043,
        13714589910668449566,
        10639034072771185213,
        14148790895768484219,
        18341268649720100165,
        3096672942770686236,
    ],
    [
        12277596046563557393,
        400461754528604020,
        12955488253560265444,
        11773677676764285572,
        4833837465239476573,
        17645852643693996619,
        6605134696140007471,
        588040525114200273,
    ],
    [
        11001741536026769411,
        17917086578469406776,
        14893530806420712543,
        727997185253761138,
        3443873847340254325,
        13095911531247069692,
        8330737046680948619,
        6014364575875986011,
    ],
    [
        16851679856681761121,
        17817965496543149594,
        12823640325246269760,
        13685256787930775147,
        4682652317564502291,
        4233879762155685988,
        11097258179564187322,
        10804761421745472094,
    ],
];