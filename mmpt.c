#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <vkr.h>
#include <string.h>

#define BRANCHES_AMOUNT 16
#define MAX_KEY_LEN 32

// leaf = [path_len, value, path]
// ext = [path_len, link, path]
// branch = [value_len, (16 * link), value]
#define LEAF_VALUE 1
#define LEAF_PATH 1 + hash_len
#define EXT_LINK 1
#define EXT_PATH hash_len + 1
#define BRANCH_ON_POS(pos) (1 + hash_len * pos)
#define BRANCH_VALUE 1 + hash_len *BRANCHES_AMOUNT

#define get_branch_child(branch, pos) branch + BRANCH_ON_POS(pos)
#define node_first_len(node) (node[0] & 0b00011111)
#define get_path_mem_size(node) ((node_first_len(node) >> 1) + (node_first_len(node) & 1))
#define is_ext(node) (node[0] & 0b11000000) == 0
#define is_leaf(node) (node[0] & 0b11000000) == 0b01000000
#define is_branch(node) (node[0] & 0b10000000) == 0b10000000

#define EXT_PREF 0b00000000    // last 6 bits for size of array
#define LEAF_PREF 0b01000000   // last 6 bits for size of array
#define BRANCH_PREF 0b10000000 // last 6 bits for size of array

#define FINALIZE_EXT(ext, ext_len, is_root) save_node(ext, ext_len, is_root)
#define FINALIZE_LEAF(leaf, leaf_len, is_root) save_node_with_value(leaf, leaf_len, is_root, leaf + LEAF_VALUE)
#define FINALIZE_LEAF_WITHOUT_VAL(leaf, leaf_len, is_root) save_node(leaf, leaf_len, is_root)
#define FINALIZE_BRANCH_WITH_VAL(branch, is_root) save_node_with_value(branch, BRANCH_VALUE + hash_len, is_root, branch + BRANCH_VALUE)
#define FINALIZE_BRANCH_WITHOUT_VAL(branch, is_root) save_node(branch, BRANCH_VALUE + hash_len * (branch[0] & 1), is_root)

#define isZeros(memory, size) (*memory == 0) && memcmp(memory, memory + 1, size - 1) == 0

uint16_t hash_len;

void shifted_memcpy(uint8_t dest[], uint8_t src[], uint8_t n)
{
    for (uint8_t i = 0; i < n; i++)
    {
        *dest++ = (*src++ << 4) | (*src >> 4);
    }
}

uint8_t *create_leaf_hash(uint8_t path[], uint8_t path_len, bool offset, bool is_root, uint8_t *set_val)
{
    uint8_t path_mem_len = (path_len >> 1) + (path_len & 1);
    uint8_t leaf_len = LEAF_PATH + path_mem_len;
    uint8_t *leaf = malloc(leaf_len);
    leaf[0] = path_len | LEAF_PREF;
    if (offset)
    {
        shifted_memcpy(leaf + LEAF_PATH, path, path_mem_len);
    }
    else
    {
        memcpy(leaf + LEAF_PATH, path, path_mem_len);
    }
    if (set_val != NULL)
    {
        memcpy(leaf + LEAF_VALUE, set_val, hash_len);
        mylog(157);
        return FINALIZE_LEAF_WITHOUT_VAL(leaf, leaf_len, is_root);
    }
    else
    {
        mylog(158);
        return FINALIZE_LEAF(leaf, leaf_len, is_root);
    }
}

// child_node - hash of child node
uint8_t *create_extension_hash(uint8_t path[], uint8_t path_len, uint8_t *child_node, bool offset, bool is_root)
{
    if (path_len == 0)
    {
        return child_node;
    }
    uint8_t path_mem_len = (path_len >> 1) + (path_len & 1);
    uint8_t ext_len = EXT_PATH + path_mem_len;
    uint8_t *ext = malloc(ext_len);
    memcpy(ext + EXT_LINK, child_node, hash_len);
    ext[0] = path_len | EXT_PREF;
    if (offset)
    {
        shifted_memcpy(ext + EXT_PATH, path, path_mem_len);
    }
    else
    {
        memcpy(ext + EXT_PATH, path, path_mem_len);
    }
    return FINALIZE_EXT(ext, ext_len, is_root);
}

uint8_t *create_branch(bool has_value)
{
    uint8_t *branch = malloc(BRANCH_VALUE + has_value * hash_len);
    memset(branch + 1, 0, (BRANCHES_AMOUNT + has_value) * hash_len);
    branch[0] = BRANCH_PREF | has_value;
    return branch;
}

uint8_t get_nibble(uint8_t key[], uint8_t number)
{
    return (number & 1) ? key[number >> 1] & 0b1111 : key[number >> 1] >> 4;
}

uint8_t *copy_leaf(uint8_t leaf[])
{
    uint16_t size = LEAF_PATH + get_path_mem_size(leaf);
    return memcpy(malloc(size), leaf, size);
}

uint8_t *copy_branch(uint8_t branch[])
{
    uint16_t size = BRANCH_VALUE + hash_len;
    return memcpy(malloc(size), branch, size);
}

uint8_t *copy_ext(uint8_t ext[])
{
    uint16_t size = EXT_PATH + node_first_len(ext);
    return memcpy(malloc(size), ext, size);
}

void insert(uint8_t *root, uint8_t key[], size_t key_len, uint16_t in_hash_len)
{
    hash_len = in_hash_len;
    if (root == NULL)
    {
        create_leaf_hash(key, key_len, false, true, NULL);
        return;
    }
    root = get_node_by_hash(root, true);

    u_int8_t i = 0;
    uint8_t node_counter = 0;
    uint8_t hash_counter = 0;

    uint8_t *prev = root;
    uint8_t *node = root;
    uint8_t *hash_path[MAX_KEY_LEN];
    uint8_t *node_path[MAX_KEY_LEN];
    while (1)
    {
        mylog(node[0]);
        if (is_branch(node))
        {
            uint8_t *old_prev = prev;
            node = copy_branch(node);
            mylog(100);
            if (i == key_len)
            {
                node[0] = BRANCH_PREF | 1;
                memcpy(prev, FINALIZE_BRANCH_WITH_VAL(node, prev == root), hash_len);
                mylog(101);
                break;
            }
            prev = get_branch_child(node, get_nibble(key, i));
            mylog(102);
            i++;
            if (isZeros(prev, hash_len))
            {
                memcpy(prev, create_leaf_hash(key + (i >> 1), key_len - i, i & 1, false, NULL), hash_len);
                memcpy(old_prev, FINALIZE_BRANCH_WITHOUT_VAL(node, prev == root), hash_len);
                mylog(103);
                break;
            }
            node_path[node_counter++] = node;
            hash_path[hash_counter++] = prev;
            node = get_node_by_hash(prev, false);
            mylog(104);
        }
        else if (is_leaf(node))
        {
            uint8_t com_pref_len = 0;
            uint8_t node_len = node_first_len(node);
            while (i != key_len && com_pref_len != node_len && get_nibble(key, i) == get_nibble(node + LEAF_PATH, com_pref_len))
            {
                i++;
                com_pref_len++;
            }
            if (i == key_len && com_pref_len == node_len)
            {
                mylog(505);
                memcpy(prev, FINALIZE_LEAF(copy_leaf(node), LEAF_PATH + (node_len >> 1) + (node_len & 1), prev == root), hash_len);
                mylog(50);
                break;
            }
            else
            {
                uint8_t *old_leaf = node;
                if (i == key_len)
                {
                    mylog(51);
                    node = create_branch(true);
                    mylog(52);
                    uint8_t *child = get_branch_child(node, get_nibble(old_leaf + LEAF_PATH, com_pref_len));
                    com_pref_len++;
                    uint8_t *new_leaf = create_leaf_hash(old_leaf + LEAF_PATH + (com_pref_len >> 1), node_len - com_pref_len, com_pref_len & 1, false, old_leaf + LEAF_VALUE);
                    memcpy(child, new_leaf, hash_len);
                    mylog(53);
                    com_pref_len--;
                    node = FINALIZE_BRANCH_WITH_VAL(node, prev == root && com_pref_len == 0);
                }
                else
                {
                    if (node_len == com_pref_len)
                    {
                        mylog(54);
                        node = create_branch(true);
                        mylog(55);
                        memcpy(node + BRANCH_VALUE, old_leaf + LEAF_VALUE, hash_len);
                        uint8_t *child = get_branch_child(node, get_nibble(key, i));
                        i++;
                        memcpy(child, create_leaf_hash(key + (i >> 1), key_len - i, i & 1, false, NULL), hash_len);
                    }
                    else
                    {
                        mylog(56);
                        node = create_branch(false);
                        uint8_t *child = get_branch_child(node, get_nibble(key, i));
                        i++;
                        mylog(57);
                        memcpy(child, create_leaf_hash(key + (i >> 1), key_len - i, i & 1, false, NULL), hash_len);
                        child = get_branch_child(node, get_nibble(old_leaf + LEAF_PATH, com_pref_len));
                        com_pref_len++;
                        mylog(58);
                        memcpy(child, create_leaf_hash(old_leaf + LEAF_PATH + (com_pref_len >> 1), node_len - com_pref_len, com_pref_len & 1, false, old_leaf + LEAF_VALUE), hash_len);
                        com_pref_len--;
                    }
                    node = FINALIZE_BRANCH_WITHOUT_VAL(node, prev == root && com_pref_len == 0);
                    mylog(59);
                }

                if (com_pref_len != 0)
                {
                    mylog(60);
                    node = create_extension_hash(old_leaf + LEAF_PATH, com_pref_len, node, false, prev == root);
                }
            }
            memcpy(prev, node, hash_len);
            break;
        }
        else // EXTENSION CASE
        {
            uint8_t com_pref_len = 0;
            uint8_t node_len = node_first_len(node);
            while (i != key_len && com_pref_len != node_len && get_nibble(key, i) == get_nibble(node + EXT_PATH, com_pref_len))
            {
                i++;
                com_pref_len++;
            }
            if (com_pref_len == node_len)
            {
                mylog(1000);
                node = copy_ext(node);
                node_path[node_counter++] = node;
                prev = node + EXT_LINK;
                node = get_node_by_hash(prev, false);
            }
            else
            {
                uint8_t *old_ext = node;
                if (i == key_len)
                {
                    mylog(1001);
                    node = create_branch(true);
                    uint8_t *child = get_branch_child(node, get_nibble(old_ext + EXT_PATH, com_pref_len));
                    com_pref_len++;
                    memcpy(child, create_extension_hash(old_ext + EXT_PATH + (com_pref_len >> 1), node_len - com_pref_len, old_ext + EXT_LINK, com_pref_len & 1, false), hash_len);
                    node = FINALIZE_BRANCH_WITH_VAL(node, prev == root && com_pref_len == 0);
                }
                else
                {
                    mylog(1002);
                    node = create_branch(false);
                    uint8_t *child = get_branch_child(node, get_nibble(old_ext + EXT_PATH, com_pref_len));
                    com_pref_len++;
                    memcpy(child, create_extension_hash(old_ext + EXT_PATH + (com_pref_len >> 1), node_len - com_pref_len, old_ext + EXT_LINK, com_pref_len & 1, false), hash_len);
                    child = get_branch_child(node, get_nibble(key, i));
                    i++;
                    memcpy(child, create_leaf_hash(key + (i >> 1), key_len - i, i & 1, false, NULL), hash_len);
                    node = FINALIZE_BRANCH_WITHOUT_VAL(node, prev == root && com_pref_len == 0);
                }

                com_pref_len--;
                if (com_pref_len != 0)
                {
                    mylog(1003);
                    node = create_extension_hash(old_ext + EXT_PATH, com_pref_len, node, false, prev == root);
                }
                memcpy(prev, node, hash_len);
                break;
            }
        }
    }
    node_counter--;
    prev = NULL;
    while (node_counter != 255)
    {
        mylog(1004);
        uint8_t *node = node_path[node_counter];
        if (is_branch(node))
        {
            if (prev != NULL)
                memcpy(hash_path[--hash_counter], prev, hash_len);
            prev = FINALIZE_BRANCH_WITHOUT_VAL(node, node_counter == 0);
        }
        else
        {
            if (prev != NULL)
                memcpy(node + EXT_LINK, prev, hash_len);
            prev = FINALIZE_EXT(node, EXT_PATH + get_path_mem_size(node), node_counter == 0);
        }
        node_counter--;
    }
}

uint8_t *get_value(uint8_t *root, uint8_t key[], uint32_t key_len, uint16_t in_hash_len)
{
    hash_len = in_hash_len;
    mylog_s("get val - 1");
    mylog(root[0]);
    root = get_node_by_hash(root, true);
    mylog_s("get val - 2");
    u_int8_t i = 0;
    while (1)
    {
        if (is_branch(root))
        {
            mylog_s("get val - branch 1");
            if (i == key_len)
            {
                if (root[0] & 1)
                {
                    return root + BRANCH_VALUE;
                }
                break;
            }
            uint8_t *new_hash = get_branch_child(root, get_nibble(key, i));
            if (isZeros(new_hash, hash_len))
                break;
            root = get_node_by_hash(new_hash, false);
            i++;
        }
        else
        {
            uint8_t node_len = node_first_len(root);
            uint8_t com_pref_len = 0;
            if (is_leaf(root))
            {
                mylog(777);
                while (i != key_len && com_pref_len != node_len && get_nibble(key, i) == get_nibble(root + LEAF_PATH, com_pref_len))
                {
                    i++;
                    com_pref_len++;
                }
                if (i == key_len && com_pref_len == node_len)
                {
                    return root + LEAF_VALUE;
                }
                break;
            }
            else
            {
                mylog(333);
                while (i != key_len && com_pref_len != node_len && get_nibble(key, i) == get_nibble(root + EXT_PATH, com_pref_len))
                {
                    i++;
                    com_pref_len++;
                }
                if (com_pref_len == node_len)
                {
                    root = get_node_by_hash(root + EXT_LINK, false);
                    if (root == NULL)
                        break;
                }
                else
                {
                    break;
                }
            }
        }
    }
    return NULL;
}

uint8_t *merkle_proof(uint8_t *root, uint8_t key[], uint32_t key_len, uint16_t in_hash_len)
{
    hash_len = in_hash_len;
    mylog_s("mrk prf - 1");
    mylog(root[0]);
    uint8_t *root_hash = root;
    root = get_node_by_hash(root, true);
    mylog_s("mrk prf - 2");
    u_int8_t i = 0;
    while (1)
    {
        if (is_branch(root))
        {
            mylog_s("mrk prf - branch 1");
            if (!validate_hash(root, BRANCH_VALUE + hash_len * root[0], root_hash))
            {
                return root_hash;
            }
            if (i == key_len)
            {
                if ((root[0] & 1) && validate_value_hash(root + BRANCH_VALUE))
                {
                    return NULL;
                }
                break;
            }
            root_hash = get_branch_child(root, get_nibble(key, i));
            if (isZeros(root_hash, hash_len))
                break;
            root = get_node_by_hash(root_hash, false);
            i++;
        }
        else
        {
            uint8_t node_len = node_first_len(root);
            uint8_t com_pref_len = 0;
            if (is_leaf(root))
            {
                mylog_s("mrk prf - leaf 1");
                while (i != key_len && com_pref_len != node_len && get_nibble(key, i) == get_nibble(root + LEAF_PATH, com_pref_len))
                {
                    i++;
                    com_pref_len++;
                }
                if (i == key_len && com_pref_len == node_len && validate_value_hash(root + LEAF_VALUE))
                {
                    return NULL;
                }
                break;
            }
            else
            {
                mylog_s("mrk prf - ext 1");
                while (i != key_len && com_pref_len != node_len && get_nibble(key, i) == get_nibble(root + EXT_PATH, com_pref_len))
                {
                    i++;
                    com_pref_len++;
                }
                root_hash = root + EXT_LINK;
                if (com_pref_len == node_len)
                {
                    root = get_node_by_hash(root_hash, false);
                    if (root == NULL)
                        break;
                }
                else
                {
                    break;
                }
            }
        }
    }
    return root_hash;
}

uint8_t *validate_rec(uint8_t *root, bool is_root)
{
    mylog_s("vld all - 1");
    mylog(root[0]);
    uint8_t *root_hash = root;
    root = get_node_by_hash(root, is_root);
    mylog_s("vld all - 2");
    while (1)
    {
        if (is_branch(root))
        {
            mylog_s("vld all - branch 1");
            if (!validate_hash(root, BRANCH_VALUE + hash_len * root[0], root_hash))
            {
                return root_hash;
            }
            if ((root[0] & 1) && !validate_value_hash(root + BRANCH_VALUE))
            {
                return root_hash;
            }
            for (uint8_t i = 0; i < BRANCHES_AMOUNT; i++)
            {
                root_hash = get_branch_child(root, i);
                if (isZeros(root_hash, hash_len))
                    continue;
                root_hash = validate_rec(root_hash, false);
                if (root_hash != NULL) 
                {
                    return root_hash;
                }
            }
        }
        else
        {
            if (is_leaf(root))
            {
                mylog_s("vld all - leaf 1");
                if (!validate_value_hash(root + LEAF_VALUE))
                {
                    return root + LEAF_VALUE;
                }
            }
            else
            {
                mylog_s("vld all - ext 1");
                root_hash = validate_rec(root + EXT_LINK, false);
                if (root_hash != NULL) 
                {
                    return root_hash;
                }
            }
        }
    }
    return NULL;
}


uint8_t *validate_all(uint8_t *root, uint16_t in_hash_len)
{
    hash_len = in_hash_len;
    validate_rec(root, true);
}