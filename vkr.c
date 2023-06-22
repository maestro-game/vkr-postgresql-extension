#include "postgres.h"
#include "fmgr.h"
PG_MODULE_MAGIC;

#include "executor/spi.h"

#include "libpq/pqformat.h"
#include "catalog/pg_type.h"
#include "utils/array.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include <string.h>
#include "mmpt.h"

#include <access/amapi.h>
#include <access/heapam.h>
#include <access/htup_details.h>
#include <access/table.h>
#include <access/tableam.h>
#include <catalog/indexing.h>
#include <utils/builtins.h>
#include <utils/fmgroids.h>
#include <utils/rel.h>
#include <utils/snapmgr.h>

#include <openssl/evp.h>

#define RANDOM_NAME_LEN 20

typedef struct
{
    char vl_len_[4];
    int16 block_table_len;
    int16 hash_len;
    char string[];
} MMPT;

PG_FUNCTION_INFO_V1(mmpt_in);
Datum mmpt_in(PG_FUNCTION_ARGS)
{

    char *str = (char *)PG_GETARG_CSTRING(0);
    char block_table[1024];
    char hash_alg[1024];
    int hash_len;
    MMPT *mmpt;

    if (sscanf(str, "(%[^,],%[^,],%d)", block_table, hash_alg, &hash_len) != 3)
        ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
                        errmsg("invalid input syntax for type MMPT: \"%s\"", str)));

    int16 block_table_len = strlen(block_table) + 1;
    size_t hash_alg_len = strlen(hash_alg) + 1;
    size_t size = VARHDRSZ + 2 * sizeof(int16) + (block_table_len + hash_alg_len) * sizeof(char);
    mmpt = (MMPT *)palloc(size);
    mmpt->block_table_len = block_table_len;
    mmpt->hash_len = hash_len;
    SET_VARSIZE(mmpt, size);
    memcpy(mmpt->string, block_table, block_table_len);
    memcpy(mmpt->string + block_table_len, hash_alg, hash_alg_len);
    PG_RETURN_POINTER(mmpt);
}

PG_FUNCTION_INFO_V1(mmpt_out);
Datum mmpt_out(PG_FUNCTION_ARGS)
{
    MMPT *mmpt = (MMPT *)PG_GETARG_POINTER(0);
    PG_RETURN_CSTRING(psprintf("(%s,%s,%d)", mmpt->string, mmpt->string + mmpt->block_table_len, mmpt->hash_len));
}

PG_FUNCTION_INFO_V1(create_mmpt);
Datum create_mmpt(PG_FUNCTION_ARGS)
{
    char *hash_alg = PG_GETARG_CSTRING(0);
    int16 hash_len = PG_GETARG_INT16(1);
    MMPT *result;

    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    char block_table[RANDOM_NAME_LEN + 6] = "mmpt_";
    for (int i = 0; i < RANDOM_NAME_LEN; i++)
    {
        int index = rand() % (sizeof(charset) - 1);
        block_table[i + 5] = charset[index];
    }
    block_table[RANDOM_NAME_LEN + 5] = '\0';

    size_t hash_alg_len = strlen(hash_alg) + 1;
    size_t size = VARHDRSZ + 2 * sizeof(int16) + (RANDOM_NAME_LEN + 6 + hash_alg_len) * sizeof(char);
    result = (MMPT *)palloc(size);
    result->hash_len = hash_len;
    result->block_table_len = RANDOM_NAME_LEN + 6;
    SET_VARSIZE(result, size);
    memcpy(result->string, block_table, RANDOM_NAME_LEN + 6);
    memcpy(result->string + RANDOM_NAME_LEN + 6, hash_alg, hash_alg_len);

    SPI_connect();

    if (SPI_exec(psprintf("create table %s(hash bytea primary key, value bytea); create table %s_r(hash bytea primary key, id serial not null, value bytea); create table %s_v(hash bytea primary key, value text);",
                          block_table, block_table, block_table),
                 1) != SPI_OK_UTILITY)
    {
        ereport(ERROR, (errcode(ERRCODE_SQL_ROUTINE_EXCEPTION),
                        errmsg("tables for MMPT wasn't created")));
    }

    SPI_finish();
    PG_RETURN_POINTER(result);
}

MMPT *mmpt;
bytea *value;

const EVP_MD_CTX *mdctx;
const EVP_MD *md;

void init_digest()
{
    OpenSSL_add_all_digests();
    md = EVP_MD_fetch(NULL, mmpt->string + mmpt->block_table_len, NULL);
    mdctx = EVP_MD_CTX_new();
}

#define name_to_oid(name) DatumGetObjectId(DirectFunctionCall1(to_regclass, CStringGetTextDatum(name)))

bool validate_hash(uint8_t input[], uint16_t input_len, uint8_t expected[])
{
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, input_len);
    uint8_t *actual = (uint8_t *)palloc(mmpt->hash_len);
    EVP_DigestFinal_ex(mdctx, actual, NULL);
    return memcmp(actual, expected, mmpt->hash_len) == 0;
}

bool validate_value_hash(uint8_t hash[])
{
    ScanKeyData skey[1];
    Oid tbl_oid = name_to_oid(psprintf("%s_v", mmpt->string));
    Oid idx_oid = name_to_oid(psprintf("%s_v_pkey", mmpt->string));
    uint16 struct_len = mmpt->hash_len + VARHDRSZ;
    bytea *hash_bytea = (bytea *)palloc(struct_len);
    SET_VARSIZE(hash_bytea, struct_len);
    memcpy(VARDATA(hash_bytea), hash, mmpt->hash_len);

    Relation rel = table_open(tbl_oid, AccessShareLock);
    Relation idxrel = index_open(idx_oid, AccessShareLock);
    IndexScanDesc scan = index_beginscan(rel, idxrel, GetTransactionSnapshot(), 1, 0);
    ScanKeyInit(&skey[0], 1, BTEqualStrategyNumber, F_BYTEAEQ, PointerGetDatum(hash_bytea));
    index_rescan(scan, skey, 1, NULL, 0);
    TupleTableSlot* slot = table_slot_create(rel, NULL);
    Datum values[2];
    bool isnull[2];
    if (index_getnext_slot(scan, ForwardScanDirection, slot))
    {
        bool should_free;
        HeapTuple tup = ExecFetchSlotHeapTuple(slot, false, &should_free);
        heap_deform_tuple(tup, RelationGetDescr(rel), values, isnull);
        if(should_free) heap_freetuple(tup);
    } else {
        ereport(ERROR, (errcode(ERRCODE_SQL_ROUTINE_EXCEPTION), errmsg("record wasn't found for leaf")));
    }
    index_endscan(scan);
    ExecDropSingleTupleTableSlot(slot);
    index_close(idxrel, AccessShareLock);
    table_close(rel, AccessShareLock);
    bytea *value_bytea = DatumGetByteaP(values[1]);
    return validate_hash(VARDATA(value_bytea), VARSIZE_ANY_EXHDR(value_bytea), hash);
}

bytea *hash(uint8_t input[], uint16_t input_len)
{
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, input_len);
    uint16 struct_len = mmpt->hash_len + VARHDRSZ;
    bytea *hash_bytea = (bytea *)palloc(struct_len);
    SET_VARSIZE(hash_bytea, struct_len);
    EVP_DigestFinal_ex(mdctx, VARDATA(hash_bytea), NULL);
    return hash_bytea;
}

// r - 0, _ - 1, v - 2
bool hash_exists(bytea *hash_bytea, int table_specie)
{
    ScanKeyData skey[1];
    Oid tbl_oid;
    Oid idx_oid;
    if (table_specie == 1) {
        tbl_oid = name_to_oid(mmpt->string);
        idx_oid = name_to_oid(psprintf("%s_pkey", mmpt->string));
    } else {
        if (table_specie == 0) {
            tbl_oid = name_to_oid(psprintf("%s_r", mmpt->string));
            idx_oid = name_to_oid(psprintf("%s_r_pkey", mmpt->string));
        } else {
            tbl_oid = name_to_oid(psprintf("%s_v", mmpt->string));
            idx_oid = name_to_oid(psprintf("%s_v_pkey", mmpt->string));
        }
    }
    Relation rel = table_open(tbl_oid, AccessShareLock);
    Relation idxrel = index_open(idx_oid, AccessShareLock);
    IndexScanDesc scan = index_beginscan(rel, idxrel, GetTransactionSnapshot(), 1, 0);
    ScanKeyInit(&skey[0], 1, BTEqualStrategyNumber, F_BYTEAEQ, PointerGetDatum(hash_bytea));
    index_rescan(scan, skey, 1, NULL, 0);
    TupleTableSlot* slot = table_slot_create(rel, NULL);
    bool result = index_getnext_slot(scan, ForwardScanDirection, slot);
    index_endscan(scan);
    ExecDropSingleTupleTableSlot(slot);
    index_close(idxrel, AccessShareLock);
    table_close(rel, AccessShareLock);
    return result;
}

bytea *write_mmpt_value()
{
    bytea *hash_bytea = hash(VARDATA(value), VARSIZE_ANY_EXHDR(value));
    if (!hash_exists(hash_bytea, 2)) {
        bool nulls[] = {false, false};
        Oid tbl_oid = name_to_oid(psprintf("%s_v", mmpt->string));
        Relation rel = table_open(tbl_oid, RowExclusiveLock);
        Datum values[] = {PointerGetDatum(hash_bytea), PointerGetDatum(value)};
        HeapTuple tup = heap_form_tuple(RelationGetDescr(rel), values, nulls);
        CatalogTupleInsert(rel, tup);
        heap_freetuple(tup);
        table_close(rel, RowExclusiveLock);
    }
    return hash_bytea;
}

uint8_t *get_node_non_root(uint8_t hash[])
{
    ScanKeyData skey[1];
    Oid tbl_oid = name_to_oid(mmpt->string);
    Oid idx_oid = name_to_oid(psprintf("%s_pkey", mmpt->string));
    uint16 struct_len = mmpt->hash_len + VARHDRSZ;
    bytea *hash_bytea = (bytea *)palloc(struct_len);
    SET_VARSIZE(hash_bytea, struct_len);
    memcpy(VARDATA(hash_bytea), hash, mmpt->hash_len);

    Relation rel = table_open(tbl_oid, AccessShareLock);
    Relation idxrel = index_open(idx_oid, AccessShareLock);
    IndexScanDesc scan = index_beginscan(rel, idxrel, GetTransactionSnapshot(), 1, 0);
    ScanKeyInit(&skey[0], 1, BTEqualStrategyNumber, F_BYTEAEQ, PointerGetDatum(hash_bytea));
    index_rescan(scan, skey, 1, NULL, 0);
    TupleTableSlot* slot = table_slot_create(rel, NULL);
    Datum values[2];
    bool isnull[2];
    if (index_getnext_slot(scan, ForwardScanDirection, slot))
    {
        bool should_free;
        HeapTuple tup = ExecFetchSlotHeapTuple(slot, false, &should_free);
        heap_deform_tuple(tup, RelationGetDescr(rel), values, isnull);
        if(should_free) heap_freetuple(tup);
    } else {
        ereport(ERROR, (errcode(ERRCODE_SQL_ROUTINE_EXCEPTION), errmsg("record wasn't found for node")));
    }
    index_endscan(scan);
    ExecDropSingleTupleTableSlot(slot);
    index_close(idxrel, AccessShareLock);
    table_close(rel, AccessShareLock);
    return VARDATA(DatumGetByteaP(values[1]));
}

uint8_t *get_root_node(uint8_t hash[])
{
    ScanKeyData skey[1];
    Oid tbl_oid = name_to_oid(psprintf("%s_r", mmpt->string));
    Oid idx_oid = name_to_oid(psprintf("%s_r_pkey", mmpt->string));
    uint16 struct_len = mmpt->hash_len + VARHDRSZ;
    bytea *hash_bytea = (bytea *)palloc(struct_len);
    SET_VARSIZE(hash_bytea, struct_len);
    memcpy(VARDATA(hash_bytea), hash, mmpt->hash_len);

    Relation rel = table_open(tbl_oid, AccessShareLock);
    Relation idxrel = index_open(idx_oid, AccessShareLock);
    IndexScanDesc scan = index_beginscan(rel, idxrel, GetTransactionSnapshot(), 1, 0);
    ScanKeyInit(&skey[0], 1, BTEqualStrategyNumber, F_BYTEAEQ, PointerGetDatum(hash_bytea));
    index_rescan(scan, skey, 1, NULL, 0);
    TupleTableSlot* slot = table_slot_create(rel, NULL);
    Datum values[3];
    bool isnull[3];
    if (index_getnext_slot(scan, ForwardScanDirection, slot))
    {
        bool should_free;
        HeapTuple tup = ExecFetchSlotHeapTuple(slot, false, &should_free);
        heap_deform_tuple(tup, RelationGetDescr(rel), values, isnull);
        if(should_free) heap_freetuple(tup);
    } else {
        ereport(ERROR, (errcode(ERRCODE_SQL_ROUTINE_EXCEPTION), errmsg("record wasn't found for root")));
    }
    index_endscan(scan);
    ExecDropSingleTupleTableSlot(slot);
    index_close(idxrel, AccessShareLock);
    table_close(rel, AccessShareLock);
    return VARDATA(DatumGetByteaP(values[2]));
}

uint8_t *get_node_by_hash(uint8_t hash[], bool is_root)
{
    if (!is_root) {
        return get_node_non_root(hash);
    } 
    else {
        return get_root_node(hash);
    }
}

uint8_t *save_node_no_root(uint8_t content[], uint16_t content_len)
{
    bytea *hash_bytea = hash(content, content_len);
    if (!hash_exists(hash_bytea, 1)) {
        bool nulls[] = {false, false};
        Oid tbl_oid = name_to_oid(mmpt->string);
        Relation rel = table_open(tbl_oid, RowExclusiveLock);
        uint16 struct_len = content_len + VARHDRSZ;
        bytea *content_bytea = (bytea *)palloc(struct_len);
        SET_VARSIZE(content_bytea, struct_len);
        memcpy(VARDATA(content_bytea), content, content_len);
        Datum values[] = {PointerGetDatum(hash_bytea), PointerGetDatum(content_bytea)};
        HeapTuple tup = heap_form_tuple(RelationGetDescr(rel), values, nulls);;
        CatalogTupleInsert(rel, tup);
        heap_freetuple(tup);
        table_close(rel, RowExclusiveLock);
    }
    return VARDATA(hash_bytea);
}

bytea *new_root = NULL;

uint8_t *save_root(uint8_t content[], uint16_t content_len)
{
    bytea *hash_bytea = hash(content, content_len);
    if (!hash_exists(hash_bytea, 0)) {
        bool nulls[] = {false, false, false};
        Oid tbl_oid = name_to_oid(psprintf("%s_r", mmpt->string));
        Oid pkey_seq_oid = name_to_oid(psprintf("%s_r_id_seq", mmpt->string));
        int32 next_id = DatumGetInt32(DirectFunctionCall1(nextval_oid, ObjectIdGetDatum(pkey_seq_oid)));

        Relation rel = table_open(tbl_oid, RowExclusiveLock);
        uint16 struct_len = content_len + VARHDRSZ;
        bytea *content_bytea = (bytea *)palloc(struct_len);
        SET_VARSIZE(content_bytea, struct_len);
        memcpy(VARDATA(content_bytea), content, content_len);

        Datum values[] = {PointerGetDatum(hash_bytea), Int32GetDatum(next_id), PointerGetDatum(content_bytea)};
        HeapTuple tup = heap_form_tuple(RelationGetDescr(rel), values, nulls);
        CatalogTupleInsert(rel, tup);
        heap_freetuple(tup);
        table_close(rel, RowExclusiveLock);
    }
    new_root = hash_bytea;
    return VARDATA(hash_bytea);
}

uint8_t *save_node(uint8_t content[], uint16_t content_len, bool is_root)
{
    if (is_root) {
        return save_root(content, content_len);
    } else {
        return save_node_no_root(content, content_len);
    }
}

uint8_t *save_node_with_value(uint8_t content[], uint16_t content_len, bool is_root, uint8_t *hash_place)
{
    memcpy(hash_place, VARDATA(write_mmpt_value()), mmpt->hash_len);
    return save_node(content, content_len, is_root);
}

PG_FUNCTION_INFO_V1(insert_in_trie);

Datum insert_in_trie(PG_FUNCTION_ARGS)
{
    if (PG_ARGISNULL(0) || PG_ARGISNULL(2) || PG_ARGISNULL(3))
    {
        ereport(ERROR, (errcode(ERRCODE_SQL_ROUTINE_EXCEPTION),
                        errmsg("mmpt, key and value must not be null")));
    }
    mmpt = (MMPT *)PG_GETARG_POINTER(0);
    bytea *key = PG_GETARG_BYTEA_P(2);
    value = PG_GETARG_BYTEA_P(3);
    uint8_t *root = NULL;
    if (!PG_ARGISNULL(1))
    {
        root = PG_GETARG_BYTEA_P(1)->vl_dat;
    }
    init_digest();
    insert(root, VARDATA(key), VARSIZE_ANY_EXHDR(key) * 2, mmpt->hash_len);

    PG_RETURN_BYTEA_P(new_root);
}

PG_FUNCTION_INFO_V1(find_in_trie);

Datum find_in_trie(PG_FUNCTION_ARGS)
{
    mmpt = (MMPT *)PG_GETARG_POINTER(0);
    uint8_t *root = PG_GETARG_BYTEA_P(1)->vl_dat;
    bytea *key = PG_GETARG_BYTEA_P(2);

    uint8_t *val = get_value(root, VARDATA(key), VARSIZE_ANY_EXHDR(key) * 2, mmpt->hash_len);
    if (val == NULL)
        PG_RETURN_NULL();

    uint16_t struct_len = mmpt->hash_len + VARHDRSZ;
    bytea *res = (bytea *)palloc(struct_len);
    SET_VARSIZE(res, struct_len);
    memcpy(VARDATA(res), val, mmpt->hash_len);
    PG_RETURN_BYTEA_P(res);
}

PG_FUNCTION_INFO_V1(merkle_proof_key);

Datum merkle_proof_key(PG_FUNCTION_ARGS)
{
    mmpt = (MMPT *)PG_GETARG_POINTER(0);
    uint8_t *root = PG_GETARG_BYTEA_P(1)->vl_dat;
    bytea *key = PG_GETARG_BYTEA_P(2);

    init_digest();
    uint8_t *val = merkle_proof(root, key->vl_dat, VARSIZE_ANY_EXHDR(key) * 2, mmpt->hash_len);
    
    if (val == NULL)
        PG_RETURN_NULL();

    uint16_t struct_len = mmpt->hash_len + VARHDRSZ;
    bytea *res = (bytea *)palloc(struct_len);
    SET_VARSIZE(res, struct_len);
    memcpy(VARDATA(res), val, mmpt->hash_len);
    PG_RETURN_BYTEA_P(res);
}

PG_FUNCTION_INFO_V1(validate_mmpt);

Datum validate_mmpt(PG_FUNCTION_ARGS)
{

    mmpt = (MMPT *)PG_GETARG_POINTER(0);
    uint8_t *root = PG_GETARG_BYTEA_P(1)->vl_dat;

    init_digest();
    uint8_t *val = validate_all(root, mmpt->hash_len);
    
    if (val == NULL)
        PG_RETURN_NULL();

    uint16_t struct_len = mmpt->hash_len + VARHDRSZ;
    bytea *res = (bytea *)palloc(struct_len);
    SET_VARSIZE(res, struct_len);
    memcpy(VARDATA(res), val, mmpt->hash_len);
    PG_RETURN_BYTEA_P(res);
}
