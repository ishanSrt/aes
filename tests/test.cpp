#include <iostream>
#include <gtest/gtest.h>

using namespace std;

TEST(Testname, Subtest_1)
{
	// Test test
	ASSERT_TRUE(1==2);
}

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
