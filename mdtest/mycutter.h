#ifndef mycutter_h_
#define mycutter_h_


#define cut_assert_equal_int(_cut_x1, _cut_x2, _cut_msgfun)			\
	do {									\
		int	_cut_mx1 = (_cut_x1);					\
		int	_cut_mx2 = (_cut_x2);					\
		if ((_cut_mx1) != (_cut_mx2)) {					\
			printf("Assert equal failed: %d != %d\n", _cut_mx1, _cut_mx2);	\
			_cut_msgfun;						\
			printf("\n");						\
			return false;						\
		}								\
	} while (0)

#define cut_assert_not_equal_int(_cut_x1, _cut_x2, _cut_msgfun)			\
	do {									\
		int	_cut_mx1 = (_cut_x1);					\
		int	_cut_mx2 = (_cut_x2);					\
		if ((_cut_mx1) == (_cut_mx2)) {					\
			printf("Assert not equal failed: %d == %d\n", _cut_mx1, _cut_mx2);	\
			_cut_msgfun;						\
			printf("\n");						\
			return false;						\
		}								\
	} while (0)

#endif /* mycutter_h_ */

